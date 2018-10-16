/*
 * Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ------------------------------------------------------------------------------
 */

use ias_client::IasClient;
use num::ToPrimitive;
use poet2_util;
use serde_json::{from_str, Value};
use sgxffi::ffi;
use sgxffi::ffi::r_sgx_enclave_id_t;
use sgxffi::ffi::r_sgx_epid_group_t;
use sgxffi::ffi::r_sgx_signup_info_t;
use sgxffi::ffi::r_sgx_wait_certificate_t;
use std::env;
use std::error::Error;
use std::io;
use std::os::raw::c_char;
use std::str;
use std::string::String;
use std::vec::Vec;
use TomlConfig;
use validator_proto::SignupInfo;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct WaitCertificate {
    pub duration_id: String,
    pub prev_wait_cert_sig: String,
    pub prev_block_id: String,
    pub block_summary: String,
    pub block_number: u64,
    pub validator_id: String,
    pub wait_time: u64,
}

impl Default for WaitCertificate {
    fn default() -> WaitCertificate {
        WaitCertificate {
            duration_id: String::new(),
            prev_wait_cert_sig: String::new(),
            prev_block_id: String::new(),
            block_summary: String::new(),
            block_number: 0_u64,
            validator_id: String::new(),
            wait_time: 0_u64, // May be deprecated in later versions
        }
    }
}

pub struct EnclaveConfig {
    pub enclave_id: r_sgx_enclave_id_t,
    pub signup_info: r_sgx_signup_info_t,
    ias_client: IasClient,
}

impl EnclaveConfig {
    pub fn default() -> Self {
        let enclave_id = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: 0 as *mut c_char,
            basename: 0 as *mut c_char,
        };
        let signup_info = r_sgx_signup_info_t {
            handle: 0,
            poet_public_key: 0 as *mut c_char,
            poet_public_key_len: 0,
            enclave_quote: 0 as *mut c_char, //Used for IAS operations
            anti_sybil_id: 0 as *mut c_char,
            proof_data: 0 as *mut c_char,
        };

        EnclaveConfig {
            enclave_id,
            signup_info,
            ias_client: IasClient::default(),
        }
    }

    pub fn initialize_enclave(&mut self, config: TomlConfig) -> () {
        let mut eid: r_sgx_enclave_id_t = r_sgx_enclave_id_t {
            handle: 0,
            mr_enclave: 0 as *mut c_char,
            basename: 0 as *mut c_char,
        };

        // get all config parameters
        let spid_str = config.spid.as_str();

        let mut lib_path = env::current_dir().unwrap();
        lib_path.push("/project/sawtooth-poet2/src/build/bin/libpoet_enclave.signed.so");
        lib_path.push("/usr/lib/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();

        ffi::init_enclave(&mut eid, bin_path, spid_str).unwrap();
        info!("Initialized enclave");

        self.enclave_id.handle = eid.handle;
        self.enclave_id.basename = eid.basename;
        self.enclave_id.mr_enclave = eid.mr_enclave;
    }

    pub fn initialize_remote_attestation(&mut self, config: TomlConfig) -> () {
        *self.ias_client.ias_url_mut() = config.ias_url.clone();
        *self.ias_client.spid_cert_file_mut() = config.spid_cert_file.clone().into_bytes();
        self.update_sig_rl();
    }

    pub fn create_signup_info(&mut self, pub_key_hash: &Vec<u8>, nonce: String) -> SignupInfo {
        self.update_sig_rl();
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        let mut signup: r_sgx_signup_info_t = self.signup_info;
        info!("creating signup_info");

        ffi::create_signup_info(&mut eid,
                                &(poet2_util::to_hex_string(pub_key_hash.to_vec())),
                                &mut signup).unwrap();

        self.signup_info.handle = signup.handle;
        self.signup_info.poet_public_key = signup.poet_public_key;
        self.signup_info.poet_public_key_len = signup.poet_public_key_len;
        self.signup_info.enclave_quote = signup.enclave_quote;

        // If not in simulator mode then get attestation verification report
        let (poet_public_key, quote) = self.get_signup_parameters();
        let response = self.ias_client.post_verify_attestation(quote.as_ref(), None, None);
        // TODO: Check if response has valid contents
        let verification_report = response.get("verification_report").unwrap();
        let signature = response.get("signature").unwrap();

        match check_verification_report(verification_report, signature) {
            Ok(_) => debug!("Verification successful!"),
            Err(_) => panic!("Invalid attestation report"),
        };

        let proof_data_json = json!({
            "verification_report": verification_report,
            "signature": signature,
        });
        // Fill up signup information from AVR
        let proof_data = ffi::create_char_ptr_from_string(proof_data_json.to_string());
        signup.proof_data = proof_data;
        let verification_report_dict: Value = from_str(verification_report.as_str()).unwrap();
        let anti_sybil_id = ffi::create_char_ptr_from_string
            (verification_report_dict["epidPseudonym"].to_string());
        signup.anti_sybil_id = anti_sybil_id;
        SignupInfo::new(poet_public_key, proof_data_json.to_string(),
                        verification_report_dict["epidPseudonym"].to_string(), nonce)
    }

    pub fn initialize_wait_certificate(
        eid: r_sgx_enclave_id_t,
        in_prev_wait_cert: String,
        in_prev_wait_cert_sig: String,
        in_validator_id: &Vec<u8>,
        in_poet_pub_key: &String,
    ) -> u64 // duration
    {
        let mut duration: u64 = 0_u64;
        let mut eid: r_sgx_enclave_id_t = eid;
        // initialize wait certificate - to get duration from enclave
        ffi::initialize_wait_cert(&mut eid, &mut duration,
                                  &in_prev_wait_cert, &in_prev_wait_cert_sig,
                                  &poet2_util::to_hex_string(in_validator_id.to_vec()),
                                  &in_poet_pub_key).unwrap();

        debug!("duration fetched from enclave = {:x?}", duration);

        duration
    }

    pub fn finalize_wait_certificate(
        eid: r_sgx_enclave_id_t,
        in_wait_cert: String,
        in_prev_block_id: String,
        in_prev_wait_cert_sig: String,
        in_block_summary: String,
        in_wait_time: u64)
        -> (String, String) {
        let mut eid: r_sgx_enclave_id_t = eid;

        let mut wait_cert_info: r_sgx_wait_certificate_t
        = r_sgx_wait_certificate_t {
            handle: 0,
            ser_wait_cert: 0 as *mut c_char,
            ser_wait_cert_sign: 0 as *mut c_char,
        };

        let ret = ffi::finalize_wait_cert(&mut eid, &mut wait_cert_info,
                                          &in_wait_cert, &in_prev_block_id,
                                          &in_prev_wait_cert_sig,
                                          &in_block_summary, &in_wait_time);

        let wait_cert = ffi::create_string_from_char_ptr(
            wait_cert_info.ser_wait_cert as *mut c_char);

        let wait_cert_sign = ffi::create_string_from_char_ptr(
            wait_cert_info.ser_wait_cert_sign as *mut c_char);

        info!("wait certificate generated is {:?}", wait_cert);

        //release wait certificate
        let status = ffi::release_wait_certificate(&mut eid, &mut wait_cert_info);

        (wait_cert, wait_cert_sign)
    }

    pub fn verify_wait_certificate(
        eid: r_sgx_enclave_id_t,
        poet_pub_key: &String,
        wait_cert: &String,
        wait_cert_sign: &String)
        -> bool
    {
        let mut eid: r_sgx_enclave_id_t = eid;
        let ret = ffi::verify_wait_certificate(&mut eid, &wait_cert.as_str(), &wait_cert_sign.as_str(), &poet_pub_key.as_str());
        println!("status {:?}", ret);
        ret
    }

    pub fn get_epid_group(&mut self) -> String {
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        let mut epid_info: r_sgx_epid_group_t = r_sgx_epid_group_t { epid: 0 as *mut c_char };
        let ret = ffi::get_epid_group(&mut eid, &mut epid_info).unwrap();
        let epid = ffi::create_string_from_char_ptr(epid_info.epid);
        debug!("EPID group = {:?}", epid);
        epid
    }

    pub fn check_if_sgx_simulator(&mut self) -> bool {
        let mut eid: r_sgx_enclave_id_t = self.enclave_id;
        let is_sgx_simulator = ffi::is_sgx_simulator(&mut eid);
        println!("is_sgx_simulator ? {:?}", is_sgx_simulator);
        is_sgx_simulator
    }

    pub fn set_sig_revocation_list(&mut self, sig_rev_list: &String) {
        let mut eid:r_sgx_enclave_id_t = self.enclave_id;
        let ret = ffi::set_sig_revocation_list(&mut eid, &sig_rev_list.as_str()).unwrap();
        debug!("Signature revocation list has been updated");
    }

    pub fn get_signup_parameters(&mut self) ->(String, String) {
        let mut signup_data:r_sgx_signup_info_t = self.signup_info;
        let poet_pub_key = ffi::create_string_from_char_ptr(signup_data.poet_public_key as *mut c_char);
        let enclave_quote = ffi::create_string_from_char_ptr(signup_data.enclave_quote as *mut c_char);
        (poet_pub_key, enclave_quote)
    }

    pub fn update_sig_rl(&mut self) -> () {
        if self.check_if_sgx_simulator() == false {
            let epid_group = self.get_epid_group();
            let sig_rl = self.ias_client.get_signature_revocation_list(
                Option::from(epid_group.as_str()), None);
            debug!("Received SigRl of {} length", sig_rl.len());
            self.set_sig_revocation_list(&sig_rl)
        }
    }
}

fn check_verification_report(
    verification_report: &String, signature: &String) -> io::Result<()> {
    // TODO: Perform verification_report signature verification
    // let public_key = "public key information";
    // parse verification_report as json response and check if present and not present
    Ok(())
}

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

use sgxffi::ffi;
use sgxffi::ffi::r_sgx_enclave_id_t;
use sgxffi::ffi::r_sgx_signup_info_t;       
use sgxffi::ffi::r_sgx_wait_certificate_t;
use std::env;
use std::os::raw::c_char;
use std::str;
use std::vec::Vec;
use num::ToPrimitive;
use std::string::String;
use poet2_util;

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct WaitCertificate {
    pub duration_id : String,
    pub poet_block_id : String,
    pub prev_block_id : String,
    pub block_summary : String,
    pub block_number : u64,
    pub validator_id : String,
    pub wait_time : u64
}

impl Default for WaitCertificate {
    fn default() -> WaitCertificate {
        WaitCertificate {
            duration_id   : String::new(),
            poet_block_id : String::new(),
            prev_block_id : String::new(),
            block_summary : String::new(),
            block_number  : 0_u64, 
            validator_id  : String::new(),
            wait_time     : 0_u64, // May be deprecated in later versions
        }
    }
}

pub struct EnclaveConfig {
    pub enclave_id : r_sgx_enclave_id_t, 
    pub signup_info : r_sgx_signup_info_t
}

impl EnclaveConfig {
    pub fn default() -> Self {
        let eid = r_sgx_enclave_id_t { handle : 0};
        let signup_info = r_sgx_signup_info_t { handle: 0,
                          poet_public_key : 0 as *mut c_char, 
                          poet_public_key_len : 0 };

        EnclaveConfig {
            enclave_id : eid,
            signup_info: signup_info
        }
    }

    pub fn initialize_enclave(&mut self)
    {
    	let mut eid:r_sgx_enclave_id_t = r_sgx_enclave_id_t { handle: 0};

        //SPID needs to be read from config file
    	let spid_vec = vec![0x41; 32]; 
        let spid_str = str::from_utf8(&spid_vec).unwrap();

        let mut lib_path = env::current_dir().unwrap();
        lib_path.push("../build/bin/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();
    	
        ffi::init_enclave(&mut eid, bin_path, spid_str).unwrap();        
        info!("Initialized enclave");

    	self.enclave_id.handle = eid.handle;
    }

    pub fn create_signup_info(&mut self, pub_key_hash: &Vec<u8>)
    {
    	let mut eid:r_sgx_enclave_id_t =  self.enclave_id;
        let mut signup:r_sgx_signup_info_t = self.signup_info;
        info!("creating signup_info");

        ffi::create_signup_info(&mut eid, 
                                &(poet2_util::to_hex_string(pub_key_hash.to_vec())), 
                                &mut signup).unwrap();         

        self.signup_info.handle = signup.handle;
        self.signup_info.poet_public_key = signup.poet_public_key;
        self.signup_info.poet_public_key_len = signup.poet_public_key_len;
    }

    pub fn initialize_wait_certificate(
        eid:r_sgx_enclave_id_t,
        in_prev_wait_cert : String,
        in_prev_wait_cert_sig : String,
        in_validator_id : &Vec<u8>,
        in_poet_pub_key: &String
        ) -> u64 // duration
    {

        let mut duration:u64 = 0_u64;
        let mut eid:r_sgx_enclave_id_t =  eid;
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
        in_prev_block_id : String,
        in_poet_block_id: String,
        in_block_summary: String,
        in_wait_time: u64)
        -> (String, String)
    {
        
        let mut eid:r_sgx_enclave_id_t =  eid;

    	let mut wait_cert_info:r_sgx_wait_certificate_t 
                                    = r_sgx_wait_certificate_t { handle: 0,
                                        ser_wait_cert: 0 as *mut c_char,
                                        ser_wait_cert_sign: 0 as *mut c_char};

    	let ret = ffi::finalize_wait_cert(&mut eid, &mut wait_cert_info,
                                            &in_wait_cert, &in_prev_block_id,
                                            &in_poet_block_id,
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
        let mut eid:r_sgx_enclave_id_t =  eid;
        let ret = ffi::verify_wait_certificate(&mut eid, &wait_cert.as_str(), &wait_cert_sign.as_str(), &poet_pub_key.as_str());
        println!("status {:?}", ret);
        ret
    }

    pub fn get_poet_pub_key(&mut self, signup_data: r_sgx_signup_info_t) ->String {
        let poet_pub_key = ffi::create_string_from_char_ptr(signup_data.poet_public_key as *mut c_char);
        poet_pub_key
    }
    
}
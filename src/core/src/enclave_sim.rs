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

use std::sync::Mutex;
use num::bigint::BigUint;
use num::bigint::RandBigInt;
use num::ToPrimitive;
use std::f64;
use std::vec::Vec;
use std::string::String;
use sawtooth_sdk::signing::secp256k1::Secp256k1PublicKey;
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use sawtooth_sdk::signing::secp256k1::Secp256k1Context;
use sawtooth_sdk::signing::create_context;
use sawtooth_sdk::signing::Context;
use serde_json;
use rand;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WaitCertificate {
    duration_id : String,
    wait_time :  u64,
    local_mean : f64,
    block_id : String,
    prev_block_id : String,
    block_hash : String,
    block_number : u64,
    validator_id : String,
}

impl Default for WaitCertificate {
    fn default() -> WaitCertificate {
        WaitCertificate {
            duration_id   : String::new(),
            wait_time     : 0_u64,
            local_mean    : 0.0_f64,
            block_id      : String::new(),
            prev_block_id : String::new(),
            block_hash    : String::new(),
            block_number  : 0_u64, 
            validator_id  : String::new(),
        }
    }
}

pub struct PoetKeyPair {
    private_key : String,
    public_key  : String,
}

impl Default for PoetKeyPair {
    fn default() -> PoetKeyPair {
        PoetKeyPair { 
            private_key : String::new(),
            public_key : String::new(),
	}
    }
}

lazy_static! {
    static ref POETKEYPAIR: Mutex<PoetKeyPair> = Mutex::new(PoetKeyPair::default());
}
 
pub fn create_signup_info() {
    let context = Secp256k1Context::new();
    let mut poet_key_pair = PoetKeyPair::default();
    let private_key = context.new_random_private_key().unwrap();

    poet_key_pair.private_key = private_key.as_hex();
    let public_key = context.get_public_key(&*private_key).unwrap();
    poet_key_pair.public_key = public_key.as_hex();
   
    let mut poetkeypair_handle = POETKEYPAIR.lock().unwrap();
    poetkeypair_handle.private_key = poet_key_pair.private_key;
    poetkeypair_handle.public_key = poet_key_pair.public_key;
}

fn truncate_biguint_to_u64(num: &BigUint) -> u64 {
    use std::u64;
    let mask = BigUint::from(u64::MAX);
    (num & mask).to_u64().unwrap()
}

pub fn create_wait_certificate(
    in_block_id: &Vec<u8>,
    in_serialized_prev_wait_certificate: &String,
    in_block_digest: &Vec<u8>,
    in_validator_id: &Vec<u8>,
    in_block_number: u64,
    in_local_mean: f64)
    -> (String, String)
{
    let mut rng = rand::thread_rng();
    let duration = rng.gen_biguint(256);
    let minimum_duration : f64 = 1.0_f64;
    let duration64 = truncate_biguint_to_u64(&duration);
    let wait_time = minimum_duration - in_local_mean * (duration64 as f64).log10();

    let mut prev_block_id = String::new();
    if !in_serialized_prev_wait_certificate.is_empty() {
	 let prev_wait_certificate : WaitCertificate = serde_json::from_str(&in_serialized_prev_wait_certificate).unwrap();
         prev_block_id = prev_wait_certificate.block_id.to_owned();
    }

    let out_wait_certificate = WaitCertificate {
        duration_id  : duration.to_str_radix(16).to_owned(), // store durationId as hex string
        wait_time    : (wait_time as u64).to_owned(),
        local_mean   : in_local_mean.to_owned(),
        block_id     : String::from_utf8(in_block_id.to_vec()).unwrap().to_owned(),
        prev_block_id : prev_block_id.to_owned(),
        block_hash   : String::from_utf8(in_block_digest.to_vec()).unwrap().to_owned(),
        block_number : in_block_number.to_owned(),
        validator_id : String::from_utf8(in_validator_id.to_vec()).unwrap().to_owned()
    };

    let out_serialized_wait_certificate = serde_json::to_string(&out_wait_certificate).unwrap();

    let poet_private_key_str = POETKEYPAIR.lock().unwrap().private_key.to_string();
    let context = create_context("secp256k1").unwrap();
    let poet_private_key = Secp256k1PrivateKey::from_hex(&poet_private_key_str).unwrap();
   
    let wc = out_serialized_wait_certificate.clone();
 
    let out_wait_certificate_signature = context.sign(&wc.into_bytes(), &poet_private_key).unwrap();
    return (out_serialized_wait_certificate, out_wait_certificate_signature);
}

pub fn verify_wait_certificate(
    in_serialized_wait_certificate: &String,
    in_wait_certificate_signature: &String) -> bool {
        let context = create_context("secp256k1").unwrap();
        let poet_public_key_str = &POETKEYPAIR.lock().unwrap().public_key;
        let poet_public_key = Secp256k1PublicKey::from_hex(&poet_public_key_str).unwrap();
        let wc = in_serialized_wait_certificate.clone();
        let verify = context.verify(&in_wait_certificate_signature, &wc.into_bytes(), &poet_public_key).unwrap();
        return verify;
}

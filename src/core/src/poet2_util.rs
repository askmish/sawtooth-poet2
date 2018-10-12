/*
 Copyright 2018 Intel Corporation

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
------------------------------------------------------------------------------
*/

use crypto::digest::Digest;
use crypto::sha2::{Sha256, Sha512};
use sawtooth_sdk::consensus::{engine::*};
use sawtooth_sdk::signing::{create_context, PrivateKey, Signer};
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use std::fs::File;
use std::io::Read;
use std::path::Path;

const WC_DELIM_CHAR: u8 = '#' as u8; //0x23

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    strs.join("")
}

pub fn blockid_to_hex_string(blockid: BlockId) -> String {
    let mut blockid_vec = Vec::from(blockid);
    to_hex_string(blockid_vec)
}

pub fn payload_to_wc_and_sig(payload: Vec<u8>)
                             -> (String, String) {
    let delim_index = payload.iter().position(|&i| i == WC_DELIM_CHAR).unwrap();
    let payload_parts = payload.split_at(delim_index + 1);
    let mut wait_certificate = String::from_utf8(payload_parts.0.to_vec()).unwrap();
    wait_certificate.pop(); // remove trailing delim
    let wait_certificate_sig = String::from_utf8(payload_parts.1.to_vec()).unwrap();
    (wait_certificate, wait_certificate_sig)
}

/// Reads the given file as string
pub fn read_file_as_string(filename: &str) -> String {
    let mut file_handler = match File::open(filename) {
        Ok(file_present) => file_present,
        Err(error) => panic!("File not found! More Details: {}", error),
    };
    let mut read_contents = String::new();
    match file_handler.read_to_string(&mut read_contents) {
        Ok(read_without_errors) => (),
        Err(error) => panic!("Read operation failed! More Details: {}", error),
    };
    read_contents
}

/// Returns SHA256 of the passed value
pub fn sha256_from_str(input_value: &str) -> String {
    let mut sha256_calculator = Sha256::new();
    sha256_calculator.input_str(input_value);
    sha256_calculator.result_str()
}

/// Returns SHA512 of the passed value
pub fn sha512_from_str(input_value: &str) -> String {
    let mut sha512_calculator = Sha512::new();
    sha512_calculator.input_str(input_value);
    sha512_calculator.result_str()
}
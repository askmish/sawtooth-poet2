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
use hyper::{Body, Client, Method, Request, Uri};
use hyper::header;
use hyper::header::HeaderValue;
use ias_client::client_utils::read_body_as_string_from_response;
use sawtooth_sdk::consensus::{engine::*};
use sawtooth_sdk::signing::{create_context, PrivateKey, Signer};
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use tokio_core::reactor::Core;

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

/// Sends the BatchList to the REST API
pub fn send_to_rest_api(api: &str, raw_bytes: Vec<u8>) -> String {
    let body_length = raw_bytes.len();
    let bytes = Body::from(raw_bytes);
    let rest_api = "http://rest-api:8008/".to_owned() + api;
    let uri = rest_api.as_str().parse::<Uri>().unwrap();
    let client = Client::new();
    let mut request = Request::new(bytes);
    *request.method_mut() = Method::POST;
    *request.uri_mut() = uri;
    request.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    request.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from(body_length),
    );
    let response = client.request(request);
    let mut runner = Core::new().unwrap();
    match runner.run(read_body_as_string_from_response(response, None)) {
        Ok(got_response) => got_response,
        Err(error) => panic!("Unable to read response; More details {}", error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static EXPECTED_FILE_CONTENT:&'static str = "This is expected content from
The dummy file.";

    #[test]
    fn test_sha512_from_str() {
        let sha512_of_validator_tp = "06774ab4d0c0dea67a6fb29dd0fee42d89cf66e0c41f63e7058e77839f18877460f260ad7dc99d12428bb188eaa1ddf87a9d9cf59570de95e9f76773bc190e78";
        let sha512_calculated = sha512_from_str("validator_registry");
        assert_eq!(sha512_of_validator_tp, sha512_calculated)
    }

    #[test]
    fn test_sha256_from_str() {
        let sha256_of_validator_tp = "6a437209808cff53912c184ab0d3742d47c601c32367e8c34dbe34e9b923e147";
        let sha256_calculated = sha256_from_str("validator_registry");
        assert_eq!(sha256_of_validator_tp, sha256_calculated)
    }

    #[test]
    fn test_read_file_as_string() {
        let what_is_read_from_file = read_file_as_string("src/tests/resources/dummy_file.txt");
        assert_eq!(EXPECTED_FILE_CONTENT, what_is_read_from_file)
    }
}
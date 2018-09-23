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

// Import section, external crates used are as follows
extern crate futures;
extern crate hyper;
extern crate hyper_tls;
extern crate native_tls;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate tokio_core;

// What are the things used from those external crates
use client_utils::get_client;
use client_utils::read_body_as_string_from_response;
use hyper::{Body, Method, Request, Uri};
use hyper::header::HeaderValue;
use std::collections::HashMap;
use std::time::Duration;
use tokio_core::reactor::Core;

// modules defined in this crate
pub mod client_utils;
#[cfg(test)]
pub mod tests;

/// structure for storing IAS connection information
#[derive(Debug, Clone)]
pub struct IasClient {
    ias_url: String,
    spid_cert_file: Vec<u8>,
    timeout: Duration,
}

/// structure for serializing and deserializing
#[derive(Deserialize)]
struct ReadResponse {
    body: String,
    header: String,
}

/// Implement how the IasClient is going to be used
impl IasClient {
    /// constructor for IasClient
    pub fn new(url: String, cert_file: Vec<u8>, time: Option<u64>) -> Self {
        IasClient {
            // url of the IAS
            ias_url: url,
            // pem encoded certificate in u8 array as input
            spid_cert_file: cert_file,
            // timeout in seconds
            timeout: Duration::new(time.unwrap_or(300), 0),
        }
    }

    /// Get signature revocation list from Intel Attestation Server
    pub fn get_signature_revocation_list(&self, gid: Option<&str>, path: Option<&str>) -> String {
        let path_computed = match path {
            Some(path_present) => String::from(path_present),
            _ => String::from("/attestation/sgx/v2/sigrl"),
        };
        let gid_computed = match gid {
            Some(gid_present) => String::from(gid_present),
            _ => String::new(),
        };
        let final_path: String = self.ias_url.as_str().to_owned() + &path_computed + &gid_computed;
        // LOGGER.debug("Fetching SigRL from: %s", url)  Note: url.as_string()
        let url = final_path.parse::<Uri>().unwrap();
        let client = get_client(self.spid_cert_file.as_slice());
        // TODO: Add logic for request timeout
        let response = client.get(url);
        let mut runner = Core::new().unwrap();
        match runner.run(read_body_as_string_from_response(response, None)) {
            Ok(got_response) => got_response,
            Err(error) => panic!("Unable to read response; More details {}", error),
        }
    }

    /// Post verify attestation
    /// return: A dictionary containing the following:
    ///     'attestation_verification_report': The body (JSON) of the
    ///         response from ISA.
    ///     'signature': The base 64-encoded RSA-SHA256 signature of the
    ///         response body (aka, AVR) using the report key.  Will be None
    ///         if the header does not contain a signature.
    pub fn post_verify_attestation(&self, quote: &[u8], manifest: Option<&str>, nonce: Option<u64>) -> HashMap<String, String> {
        let final_path: String = self.ias_url.as_str().to_owned() + "/attestation/sgx/v2/report";
        let url = final_path.parse::<Uri>().unwrap();
        // LOGGER.debug("Posting attestation verification request to: %s", url)
        let mut post_json: HashMap<String, String> = HashMap::new();
        post_json.insert(String::from("isvEnclaveQuote"), std::str::from_utf8(quote).unwrap().to_owned());
        match manifest {
            Some(manifest_data) => {
                post_json.insert(String::from("pseManifest"), manifest_data.to_owned());
            }
            _ => (),
        };
        match nonce {
            Some(nonce_data) => {
                post_json.insert(String::from("nonce"), nonce_data.to_string().to_owned());
            }
            _ => (),
        };
        let mut req = Request::new(Body::from(serde_json::to_string(&post_json).unwrap()));
        *req.method_mut() = Method::POST;
        *req.uri_mut() = url.clone();
        req.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        // LOGGER.debug("Posting attestation evidence payload: %s", json)
        let client = get_client(self.spid_cert_file.as_slice());
        let response = client.request(req);
        // LOGGER.debug("received attestation result code: %d", response.status_code)
        // LOGGER.debug("received attestation result: %s", response.json())
        // TODO: Add logic for request timeout
        let mut runner = Core::new().unwrap();
        match runner.run(read_body_as_string_from_response(response, Option::from("x-iasreport-signature"))) {
            Ok(got_response) => {
                let deserialized: Result<ReadResponse, _> = serde_json::from_str(got_response.as_str());
                let response_to_return = match deserialized {
                    Ok(got_response) => {
                        let mut return_object: HashMap<String, String> = HashMap::new();
                        return_object.insert(String::from("verification_report"), got_response.body.as_str().to_owned());
                        return_object.insert(String::from("signature"), got_response.header.as_str().to_owned());
                        return_object
                    }
                    Err(error) => panic!("Json not encoded properly; More details: {}", error),
                };
                response_to_return
            }
            Err(error) => panic!("Unable to read response; More details {}", error),
        }
    }
}
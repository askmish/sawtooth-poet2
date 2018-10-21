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

extern crate serde_json;

use futures::future;
use futures::future::Future;
use futures::stream::Stream;
use hyper::{Body, Client, Error, StatusCode};
use hyper::client::{HttpConnector, ResponseFuture};
use hyper::header::HeaderMap;
use hyper::header::HeaderValue;
use hyper_tls::HttpsConnector;
use native_tls::{Certificate, TlsConnector};
use std::collections::HashMap;

/// Get a http and https compatible client to conenct to remote URI
pub fn get_client(pem_cert: &[u8]) -> Client<HttpsConnector<HttpConnector>, Body> {
    let cert = match Certificate::from_pem(pem_cert) {
        Ok(cert_contents) => cert_contents,
        Err(error) => panic!("Cert is not valid; More info: {}", error),
    };
    // trust the supplied root certificate
    let tls_connector = match TlsConnector::builder().add_root_certificate(cert).build() {
        Ok(tls_connector_built) => tls_connector_built,
        Err(error) => panic!("Unable to build TLS connector; More info: {}", error),
    };
    // TODO: number of threads is fixed to 4 here
    let mut http = HttpConnector::new(4);
    // allow both HTTP and HTTPS, we are using TlsConnector to build HttpsConnector
    http.enforce_http(false);
    let https = HttpsConnector::from((http, tls_connector));
    // build a client to allow both http and https URI formats
    Client::builder().build::<_, Body>(https)
}

/// Return future of body from ResponseFuture
pub fn read_body_as_string_from_response(
    response: ResponseFuture,
    header_param_to_read: Option<&'static str>
) -> impl Future<Item=String, Error=Error> {
    response
        .and_then(move |res| {
            if res.status() != StatusCode::OK {
                panic!("Bad response")
            }
            let headers = res.headers().to_owned();
            read_body_as_string(res.into_body(), header_param_to_read, headers)
        })
}

/// Read body as string
pub fn read_body_as_string(
    body: Body,
    header_param_to_read: Option<&'static str>,
    headers: HeaderMap<HeaderValue>
) -> impl Future<Item=String, Error=Error> {
    body.fold(Vec::new(), |mut vector, chunk| {
        vector.extend_from_slice(&chunk[..]);
        future::ok::<_, Error>(vector)
    })
        .and_then(move |vectors| {
            let body = String::from_utf8(vectors).unwrap();
            let to_return = match header_param_to_read {
                Some(read_param) => {
                    // Construct a json response in string {body:"", header:""}
                    let mut map: HashMap<String, String> = HashMap::new();
                    map.insert(String::from("body"), body);
                    map.insert(String::from("header"), headers.get(read_param).unwrap().to_str().unwrap().to_string());
                    serde_json::to_string(&map).unwrap()
                }
                _ => body,
            };
            future::ok(to_return)
        })
}
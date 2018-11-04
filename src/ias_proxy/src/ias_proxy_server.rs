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

extern crate futures;
extern crate hyper;
extern crate ias_client;
extern crate ias_proxy;
extern crate serde;
extern crate serde_json;
extern crate tokio_core;

use self::futures::{Future, future};
use self::hyper::{Body, Error, header::{HeaderMap, HeaderName, HeaderValue}, Method, Request, Response, Server,
                  service::service_fn, StatusCode};
use self::ias_client::ias_client::IasClient;
use self::ias_proxy::lru_cache::LruCache;
use self::tokio_core::reactor::Core;
use std::{collections::HashMap, net::SocketAddr, str::FromStr, sync::Mutex};

type ResponseBox = Box<Future<Item=Response<Body>, Error=Error> + Send>;

/// structure defining IAS proxy server
pub struct IasProxyServer {
    ias_proxy_name: String,
    ias_proxy_port: String,
    ias_client: IasClient,
}

/// response body from the IAS
#[derive(Deserialize)]
struct IasResponseBody {
    #[serde(rename = "isvEnclaveQuote")]
    isv_enclave_quote: String,
    #[serde(rename = "pseManifest")]
    pse_manifest: String,
    nonce: u64,
}

lazy_static! {
    static ref sig_rl_cache: Mutex<LruCache> = Mutex::new(LruCache::new(None));
    static ref attestation_cache: Mutex<LruCache> = Mutex::new(LruCache::new(None));
}

const SIG_RL_LINK: &str = "/attestation/sgx/v2/sigrl";
const AVR_LINK: &str = "/attestation/sgx/v2/report";

impl IasProxyServer {
    /// Create new instance of IasProxyServer
    pub fn new(config_map: HashMap<String, String>) -> Self {
        IasProxyServer {
            ias_proxy_name: config_map["proxy_name"].clone(),
            ias_proxy_port: config_map["proxy_port"].clone(),
            ias_client: IasClient::new(
                config_map["ias_url"].clone(),
                Vec::from(config_map["spid_cert_file"].as_bytes()),
                None,
            ),
        }
    }

    /// run method to start listeing on the identified port and IP
    pub fn run(&self) -> () {
        // Start the web server on the configured URL
        let path = self.ias_proxy_name.as_str().to_owned() + ":" + &self.ias_proxy_port.as_str().to_owned();
        info!("Path constructed is {}", path);
        let socket_addr: SocketAddr = match SocketAddr::from_str(&path) {
            Ok(found_addr) => found_addr,
            Err(err) => panic!("Error reading the address: {}", err),
        };
        let ias_client = self.ias_client.clone();
        // TODO: Store this server instance and call shutdown
        let new_service = move || {
            let ias_client = ias_client.clone();
            service_fn(move |req|
                respond_to_request(req, &ias_client)
            )
        };
        // Error case returns 404
        let server = Server::bind(&socket_addr).serve(new_service);
        hyper::rt::run(server.map_err(|e| {
            panic!("Server error: {}", e);
        }));
    }

    /// stop to stop listening on the port
    pub fn stop(&self) -> () {
        // TODO: Need to stop the server started
        // stop the listening thread
    }
}

fn respond_to_request(req: Request<Body>, ias_client_obj: &IasClient) -> ResponseBox {
    let path = req.uri().path().to_owned();
    let response = match *req.method() {
        // handle get request from the proxy
        Method::GET =>
            if path.contains(SIG_RL_LINK) {
                let cached = sig_rl_cache.lock().unwrap().get(path.clone());
                match cached {
                    Some(cache_content) => {
                        let mut headers = HashMap::new();
                        headers.insert(String::from("Content-type"), String::from("text/plain"));
                        headers.insert(String::from("Content-length"), cache_content["response"].len().to_string());
                        let body = Body::from(cache_content["response"].clone());
                        send_response(200, Option::from(headers), Option::from(body))
                    }
                    None => {
                        let result = ias_client_obj.get_signature_revocation_list(None, Some(path.as_str()));
                        let mut hashmap = HashMap::new();
                        hashmap.insert(String::from("code"), String::from("200"));
                        hashmap.insert(String::from("response"), result.clone());
                        sig_rl_cache.lock().unwrap().set(path, hashmap);
                        let mut headers = HashMap::new();
                        headers.insert(String::from("Content-type"), String::from("text/plain"));
                        headers.insert(String::from("Content-length"), result.len().to_string());
                        let body = Body::from(result);
                        send_response(200, Option::from(headers), Option::from(body))
                    }
                }
            } else {
                send_response(404, None, None)
            },
        Method::POST =>
            if req.uri().path().contains(AVR_LINK) {
                // read json input data
                let read_body_future = ias_client::client_utils::read_body_as_string(req.into_body(), None, HeaderMap::new());
                let mut runner = Core::new().unwrap();
                let read_body = runner.run(read_body_future).unwrap();
                let json_body: IasResponseBody = serde_json::from_str(read_body.as_str()).unwrap();
                let quote = json_body.isv_enclave_quote;
                if !quote.is_empty() {
                    // If not input the quote from json 'isvEnclaveQuote' then return 404
                    // otherwise check the cache or send the request to actual IAS server
                    let mut cached = attestation_cache.lock().unwrap().get(quote.clone());
                    let cache = match cached {
                        None => {
                            let result = ias_client_obj.post_verify_attestation(quote.as_bytes(), Option::from(json_body.pse_manifest.as_str()), Option::from(json_body.nonce));
                            attestation_cache.lock().unwrap().set(quote, result.clone());
                            Option::from(result)
                        }
                        Some(cache_present) => Option::from(cache_present),
                    };
                    match cache {
                        None => {
                            send_response(520, None, None)
                        }
                        Some(cached_content) => {
                            let body = Body::from(cached_content.get("verification_report").unwrap().clone());
                            let mut headers = HashMap::new();
                            headers.insert(String::from("x-iasreport-signature"), cached_content.get("signature").unwrap().clone());
                            headers.insert(String::from("Content-type"), String::from("application/json"));
                            headers.insert(String::from("Content-length"), (*cached_content.get("verification_report").unwrap()).len().to_string());
                            send_response(200, Option::from(headers), Option::from(body))
                        }
                    }
                } else {
                    send_response(404, None, None)
                }
            } else {
                send_response(404, None, None)
            },
        _ => send_response(404, None, None),
    };
    response
}

fn send_response(status_code: u16, headers: Option<HashMap<String, String>>, body: Option<Body>) -> ResponseBox {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::from_u16(status_code).unwrap();
    match body {
        Some(body_content) => *response.body_mut() = body_content,
        None => (),
    };
    match headers {
        Some(header_content) =>
            for (key, value) in header_content {
                response.headers_mut().insert(HeaderName::from_str(key.as_str()).unwrap(), HeaderValue::from_str(value.as_str()).unwrap());
            },
        None => (),
    }
    Box::new(future::ok(response))
}

pub fn get_proxy_server(proxy_config: HashMap<String, String>) -> IasProxyServer {

    // Read config file from config.get_config_dir()/ias_proxy_server.toml
    // Conversion to struct would have failed if fields in file doesn't match expectation
    // So the config map here has all required values set in it
    let ias_server = IasProxyServer::new(proxy_config);
    ias_server
}
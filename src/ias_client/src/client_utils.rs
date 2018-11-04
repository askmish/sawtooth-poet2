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

extern crate hyper_tls;
extern crate native_tls;

use futures::{future, future::Future, stream::Stream};
use hyper::{Body, Client, client::{HttpConnector, ResponseFuture}, Error, header::{HeaderMap, HeaderValue}, StatusCode};
use self::hyper_tls::HttpsConnector;
use self::native_tls::{Certificate, TlsConnector};
use serde_json::to_string;
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
    header_param_to_read: Option<&'static str>,
) -> impl Future<Item=String, Error=Error> {
    response
        .and_then(move |res| {
            debug!("received attestation result code: {}", res.status());
            if res.status() != StatusCode::OK {
                // TODO: This should have returned hyper::Error, but we cannot craate that object
                panic!("Bad Response")
            }
            let headers = res.headers().to_owned();
            read_body_as_string(res.into_body(), header_param_to_read, headers)
        })
}

/// Read body as string
pub fn read_body_as_string(
    body: Body,
    header_param_to_read: Option<&'static str>,
    headers: HeaderMap<HeaderValue>,
) -> impl Future<Item=String, Error=Error> {
    body.fold(Vec::new(), |mut vector, chunk| {
        vector.extend_from_slice(&chunk[..]);
        future::ok::<_, Error>(vector)
    })
        .and_then(move |vectors| {
            let body = String::from_utf8(vectors).unwrap();
            let empty_header = HeaderValue::from_str("").unwrap();
            let to_return = match header_param_to_read {
                Some(read_param) => {
                    // Construct a json response in string {body:"", header:""}
                    let mut map: HashMap<String, String> = HashMap::new();
                    let header_value = match headers.get(read_param) {
                        Some(found_header) => found_header,
                        None => &empty_header,
                    };
                    map.insert(String::from("body"), body);
                    map.insert(String::from("header"), header_value.to_str().unwrap().to_string());
                    to_string(&map).unwrap()
                }
                _ => body,
            };
            future::ok(to_return)
        })
}

#[cfg(test)]
mod tests {
    use hyper::{header::HeaderName, Response, Server, service::service_fn_ok, Uri};
    use std::{net::{Ipv4Addr, SocketAddr, SocketAddrV4}, str::FromStr, thread};
    use super::*;
    use tokio::runtime::Runtime;
    use tokio_core::reactor::Core;

    // Variable so that server is not trying to bind again
    static mut IS_INITIALIZED: bool = false;
    lazy_static! {
        static ref random_string: String = "This string is expected in body".to_string();
    }

    #[test]
    fn test_body_read_as_string() {
        let body_composed = Body::from(random_string.clone());
        let future_function_to_read_body = read_body_as_string(body_composed, None, HeaderMap::new());
        let mut runner = Core::new().unwrap();
        let what_is_read_from_body = runner.run(future_function_to_read_body).unwrap();
        assert_eq!(random_string.clone(), what_is_read_from_body)
    }

    #[test]
    fn test_body_read_as_string_with_expected_header() {
        let header1 = "header1";
        let value1 = "value1";
        let body_composed = Body::from(random_string.clone());
        let mut random_map: HeaderMap = HeaderMap::new();
        random_map.insert(header1, HeaderValue::from_str(value1).unwrap());
        let future_function_to_read_body = read_body_as_string(
            body_composed,
            Option::from(header1),
            random_map);
        let mut runner = Core::new().unwrap();
        let what_is_read_from_body = runner.run(future_function_to_read_body).unwrap();
        assert!(what_is_read_from_body.contains(value1)
            && what_is_read_from_body.contains(random_string.clone().as_str())
        )
    }

    #[test]
    fn test_body_read_as_string_with_unexpected_header() {
        let header1 = "header1";
        let value1 = "value1";
        let value2 = "unexpected";
        let body_composed = Body::from(random_string.clone());
        let mut random_map: HeaderMap = HeaderMap::new();
        random_map.insert(header1, HeaderValue::from_str(value1).unwrap());
        let future_function_to_read_body = read_body_as_string(
            body_composed,
            Option::from(header1),
            random_map);
        let mut runner = Core::new().unwrap();
        let what_is_read_from_body = runner.run(future_function_to_read_body).unwrap();
        assert!(!what_is_read_from_body.contains(value2)
            && what_is_read_from_body.contains(random_string.clone().as_str())
        )
    }

    #[test]
    fn test_read_response_body_as_string() {
        unsafe {
            if IS_INITIALIZED == false {
                mock_setup_server();
            }
        }
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(address.parse::<Uri>().unwrap());
        let mut runner = Core::new().unwrap();
        let what_is_read_from_response = runner.run(
            read_body_as_string_from_response(future_response,
                                              None)).unwrap();
        assert_eq!(random_string.clone(), what_is_read_from_response)
    }

    #[test]
    fn test_read_response_body_with_header_as_string() {
        unsafe {
            if IS_INITIALIZED == false {
                mock_setup_server();
            }
        }
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(address.parse::<Uri>().unwrap());
        let mut runner = Core::new().unwrap();
        let what_is_read_from_response = runner.run(
            read_body_as_string_from_response(future_response,
                                              Option::from("header1"))).unwrap();
        assert!(what_is_read_from_response.contains(random_string.clone().as_str())
            && what_is_read_from_response.contains("value1"))
    }

    #[test]
    fn test_read_response_body_with_invalid_header_as_string() {
        unsafe {
            if IS_INITIALIZED == false {
                mock_setup_server();
            }
        }
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(address.parse::<Uri>().unwrap());
        let mut runner = Core::new().unwrap();
        let what_is_read_from_response = runner.run(
            read_body_as_string_from_response(future_response,
                                              Option::from("header2"))).unwrap();
        assert!(what_is_read_from_response.contains(random_string.clone().as_str())
            && !what_is_read_from_response.contains("value1"))
    }

    #[test]
    fn test_get_client() {
        unsafe {
            if IS_INITIALIZED == false {
                mock_setup_server();
            }
        }
        let cert = "-----BEGIN CERTIFICATE-----
MIICaTCCAdKgAwIBAgIJAItOJYg0b5+lMA0GCSqGSIb3DQEBCwUAMEwxCzAJBgNV
BAYTAklOMQswCQYDVQQIDAJLQTELMAkGA1UEBwwCQkExDjAMBgNVBAoMBUludGVs
MRMwEQYDVQQLDApCbG9ja2NoYWluMB4XDTE4MTAyNDEyNDEwMFoXDTE5MTAyNDEy
NDEwMFowTDELMAkGA1UEBhMCSU4xCzAJBgNVBAgMAktBMQswCQYDVQQHDAJCQTEO
MAwGA1UECgwFSW50ZWwxEzARBgNVBAsMCkJsb2NrY2hhaW4wgZ8wDQYJKoZIhvcN
AQEBBQADgY0AMIGJAoGBAM/uqnOiEKD/TcshpNOr8/hD/7WAvRDcPb7IFwzoaS1t
NaheDh2W4EGd8jLPmknYGSHUL8ust2dZXTrMXxHGZWpbnEA15dboJptXEem5XoOG
04NYw6sr/r7Bv9pi1Y34JDu7vcwdK29XHSI58msGEeU3RlPB3fuWVrw6yV2oO1FZ
AgMBAAGjUzBRMB0GA1UdDgQWBBTOVWh5+ajCi7Xyq/cLDLCKVqm6/DAfBgNVHSME
GDAWgBTOVWh5+ajCi7Xyq/cLDLCKVqm6/DAPBgNVHRMBAf8EBTADAQH/MA0GCSqG
SIb3DQEBCwUAA4GBABg38E87twLUOKKwfS+bKHnp35x4eoD3Jg/e82zusADdNg6/
FG7njB5GTDXQhfdcjTo33+pzxr38jSxSEK0g9EJ3+nWqX1SFsKl7m38GOuhjzlxc
fL464/eRImnAtIPsDe+bywGUc5mq/EEiJ+90jXP1LAWgUk2Ip5Hl0BeEM34U
-----END CERTIFICATE-----";

        let client = get_client(cert.as_ref());
        let address = "http://127.0.0.1:".to_string().to_owned() + "8080";
        let future_response = client.get(address.parse::<Uri>().unwrap());
        let mut runner = Core::new().unwrap();
        let what_is_read_from_response = runner.run(
            read_body_as_string_from_response(future_response,
                                              None)).unwrap();
        assert_eq!(random_string.clone(), what_is_read_from_response)
    }

    #[test]
    #[should_panic]
    fn test_not_ok_read_response_body_with_string() {
        mock_setup_bad_server();
        let client = Client::new();
        let address = "http://127.0.0.1:".to_string().to_owned() + "8081";
        let future_response = client.get(address.parse::<Uri>().unwrap());
        let mut runner = Core::new().unwrap();
        runner.run(
            read_body_as_string_from_response(future_response,
                                              None)).unwrap();
    }

    fn mock_setup_server() {
        unsafe {
            IS_INITIALIZED = true;
        }
        let loopback_addr = Ipv4Addr::new(127, 0, 0, 1);
        // TODO: Use random port here
        let socket_addr: SocketAddr = SocketAddr::from(SocketAddrV4::new(loopback_addr, 8080));
        let new_service = move || {
            service_fn_ok(|_| {
                let mut response = Response::new(Body::from(random_string.clone()));
                response.headers_mut().insert(HeaderName::from_str("header1").unwrap(),
                                              HeaderValue::from_str("value1").unwrap());
                response
            })
        };
        let server = Server::bind(&socket_addr)
            .serve(new_service)
            .map_err(|e| panic!("server error: {}", e));

        // TODO: Force this thread to close after test case ends
        thread::spawn(|| {
            let mut handler = Runtime::new().unwrap();
            handler.block_on(server).unwrap()
        });
    }

    fn mock_setup_bad_server() {
        let loopback_addr = Ipv4Addr::new(127, 0, 0, 1);
        // TODO: Use random port here
        let socket_addr: SocketAddr = SocketAddr::from(SocketAddrV4::new(loopback_addr, 8081));
        let new_service = move || {
            service_fn_ok(|_| {
                let mut response = Response::new(Body::from(random_string.clone()));
                *response.status_mut() = StatusCode::from_u16(400).unwrap();
                response
            })
        };
        let server = Server::bind(&socket_addr)
            .serve(new_service)
            .map_err(|e| panic!("server error: {}", e));

        // TODO: Force this thread to close after test case ends
        thread::spawn(|| {
            let mut handler = Runtime::new().unwrap();
            handler.block_on(server).unwrap()
        });
    }
}
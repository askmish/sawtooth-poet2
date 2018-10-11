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

pub mod ffi;

#[cfg(test)]
mod tests {
    use super::*;
    use std::str;
    use std::os::raw::c_char;
    use std::ffi::CStr;
    use ffi::r_sgx_enclave_id_t;
    use ffi::r_sgx_signup_info_t;       
    use ffi::r_sgx_wait_certificate_t;

    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }

    //#[test]
    fn init_free_enclave_test() {
        
        let mut eid:r_sgx_enclave_id_t = r_sgx_enclave_id_t {handle : 0};
        
        //spid should be a valid UTF-8 string of length 32. create all AAAAA's
        let spid_vec = vec![0x41; 32]; 
        let spid_str = str::from_utf8(&spid_vec).unwrap();
        let mut lib_path = std::env::current_dir().unwrap();
        lib_path.push("../../build/bin/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();
        let ret = ffi::init_enclave(&mut eid, bin_path, spid_str);
        assert_eq!(ret, 0);
        
        let ret = ffi::free_enclave(&mut eid);
        assert_eq!(ret, 0);
    }
        
    
    #[test]
    fn create_wait_certificate_test(){
        println!("create_wait_certificate test");
        let mut eid:r_sgx_enclave_id_t = r_sgx_enclave_id_t {handle : 0};
        
        //spid should be a valid UTF-8 string of length 32. create all AAAAA's
        let spid_vec = vec![0x41; 32]; 
        let spid_str = str::from_utf8(&spid_vec).unwrap();        
        let mut lib_path = std::env::current_dir().unwrap();
        lib_path.push("../../build/bin/libpoet_enclave.signed.so");
        let bin_path = &lib_path.into_os_string().into_string().unwrap();

        let ret = ffi::init_enclave(&mut eid, bin_path, spid_str);
        assert_eq!(ret, 0);

        let opk_hash_vec = "ABCD" ;//[0x42; 32];
        let mut signup_info:r_sgx_signup_info_t = r_sgx_signup_info_t {handle:0,
                                                                       poet_public_key : 0 as *mut c_char, 
                                                                       poet_public_key_len : 0 };

        println!("creating signup_info");
        let ret = ffi::create_signup_info(&mut eid, &opk_hash_vec, &mut signup_info); 
        assert_eq!(ret, 0);

        let ppk_str: String = ffi::create_string_from_char_ptr(signup_info.poet_public_key as *mut c_char);
        println!("Poet Public Key : {}", ppk_str);

        //let mut duration: Vec<u8> = vec![0;32];
        let mut duration: u64 = 0x0102030405060708;     
        let prev_cert = "";
        let prev_block_id = "";
        let validator_id = "123";
        let block_summary = "this is first block";

        let mut wait_cert_info:r_sgx_wait_certificate_t = r_sgx_wait_certificate_t{ handle: 0,
                                                                                    serialized_wait_certificate: 0 as *mut c_char,
                                                                                    serialized_wait_certificate_signature: 0 as *mut c_char
                                                                                  };

        // initialize wait certificate - to get duration from enclave
        let ret = ffi::initialize_wait_cert(&mut eid, &mut duration, &prev_cert, &prev_block_id, &validator_id);
        assert_eq!(ret, 0);

        println!("duration inside rust layer 0x{:016x?}", duration);
        
        // finalize wait certificate - to get wait certificate
        let ret = ffi::finalize_wait_cert(&mut eid, &mut wait_cert_info, &prev_block_id, &block_summary);
        assert_eq!(ret, 0);
        
        let ret = ffi::release_wait_certificate(&mut eid, &mut wait_cert_info);
        assert_eq!(ret, 0);

        let ret = ffi::release_signup_info(&mut eid, &mut signup_info);        
        assert_eq!(ret, 0);
        
        let ret = ffi::free_enclave(&mut eid);
        assert_eq!(ret, 0);
    }
    
}

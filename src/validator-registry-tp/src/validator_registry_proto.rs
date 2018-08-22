/*
 * Copyright 2018 Intel Corporation.
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
 * -----------------------------------------------------------------------------
 */

use sawtooth_sdk::processor::handler::ApplyError;
use std::str::from_utf8;
use serde_json;

const VALIDATOR_NAME_LEN : usize = 64; 

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct SignupInfo {
    pub poet_public_key : String,
    pub proof_data : String,
    pub anti_sybil_id : String,
    pub nonce :String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct ValidatorInfo {
    pub name : String,
    pub id : String,
    pub signup_info : SignupInfo,
    pub txn_id : String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorRegistryPayload {
    verb : String,
    name : String,
    id   : String,
    signup_info : SignupInfo,
}

impl ValidatorRegistryPayload {
    pub fn new(payload_data: &[u8], public_key: &String) -> Result<ValidatorRegistryPayload, ApplyError> {
        let payload : ValidatorRegistryPayload;
        let payload_string = match from_utf8(&payload_data) {
            Ok(s) => s,
            Err(_) => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid payload serialization",
                )))
            }
        };

        let deserialized_payload = serde_json::from_str(&payload_string);
        if deserialized_payload.is_ok() {
            payload = deserialized_payload.unwrap();
        } else {
            return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid validator payload string",
                )));
        }

        if payload.name.len() <= 0 || payload.name.len() > VALIDATOR_NAME_LEN {
            return Err(ApplyError::InvalidTransaction(String::from(
                    format!("Invalid validator name length {}", payload.name.len()),
                )));
        }

        if payload.id != public_key.to_string() {
            return Err(ApplyError::InvalidTransaction(String::from(
                    format!("Signature mismatch on validator registration with validator {} signed by {}",
                        &payload.id,
                        &public_key),
                )));
        }

        Ok(payload)
    }

    pub fn get_verb(&self) -> String {
        self.verb.clone()
    }

    pub fn get_name(&self) -> String {
        self.name.clone()
    }

    pub fn get_id(&self) -> String {
        self.id.clone()
    }

    pub fn get_signup_info(&self) -> SignupInfo {
        self.signup_info.clone()
    }
}


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

use crypto::sha2::Sha512;
use crypto::sha2::Sha256;
use crypto::digest::Digest;

use sawtooth_sdk::messages::processor::TpProcessRequest;
use sawtooth_sdk::processor::handler::ApplyError;
use sawtooth_sdk::processor::handler::TransactionContext;
use sawtooth_sdk::processor::handler::TransactionHandler;

use validator_registry_proto::*;

use serde_json;

use std::error;
use std::fmt;

#[derive(Serialize, Deserialize, Debug, Copy, Clone)]
pub struct ValidatorRegistryPayload {
    verb : String,
    name : String,
    id   : String,
    signup_info : SignupInfo,
}

#[derive(Debug, Clone)]
struct ValueError;

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid value found")
    }
}

impl error::Error for ValueError {
    fn description(&self) -> &str {
        "invalid value found"
    }

    fn cause(&self) -> Option<&error::Error> {
        None
    }
}

pub struct ValidatorRegistryTransactionHandler {
    family_name: String,
    family_versions: Vec<String>,
    namespaces: Vec<String>,
}

impl ValidatorRegistryTransactionHandler {
    
    pub fn new() -> ValidatorRegistryTransactionHandler {
        ValidatorRegistryTransactionHandler {
            family_name: String::from("validator_registry"),
            family_versions: vec![String::from("1.0")],
            namespaces: vec![String::from(get_validator_registry_prefix().to_string())],
        }
    }         
}

impl TransactionHandler for ValidatorRegistryTransactionHandler {
    fn family_name(&self) -> String {
        self.family_name.clone()
    }

    fn family_versions(&self) -> Vec<String> {
        self.family_versions.clone()
    }

    fn namespaces(&self) -> Vec<String> {
        self.namespaces.clone()
    }


    fn _update_validator_state(&self,
                               validator_id : &String,
                               anti_sybil_id: &String,
                               validator_info: &ValidatorInfo,) -> Result <(), ValueError> {
         Ok()
    }
   
    fn _verify_signup_info(&self,
                           originator_public_key_hash: &String,
                           val_reg_payload: &ValidatorRegistryPayload,
                           context : &mut TransactionContext,) -> Result <(), ValueError> {
         let signup_info = val_reg_payload.get_SignupInfo();
         Ok()
    }

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        let txn_header = &request.header;
        let txn_public_key = match &header.as_ref() {
            Some(s) => &s.signer_public_key,
            None => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid header",
                )))
            }
        };

        let mut val_reg_payload = ValidatorRegistryPayload::new(&request.payload, &txn_public_key)?;
        let mut txn_public_key_hasher = Sha256::new();
        txn_public_key_hasher.input(txn_public_key.as_bytes());
        let mut txn_public_key_hash = txn_public_key_hasher.result_str();

        let result = self._verify_signup_info(&txn_public_key_hash, &val_reg_payload, &mut context);

        if result.is_ok() {
           let validator_info = ValidatorInfo {
                                    name : validator_name.to_owned(),
                                    id : validator_id.to_owned(),
                                    signup_info : val_reg_payload.signup_info.to_owned(),
                                    transaction_id : request.signature.clone(),};
            self._update_validator_state(&mut context,
                                &validator_id,
                                &signup_info.anti_sybil_id,
                                &validator_info);
        } else {
           return Err(ApplyError::InvalidTransaction(String::from("Invalid Signup Info")));
        }
        
        Ok()
    }
}

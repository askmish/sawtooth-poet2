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
use std::convert::From;
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorRegistryPayload {
    verb : String,
    name : String,
    id   : String,
    signup_info : SignupInfo,
}

impl From<String> for ValidatorRegistryPayload {
    fn from( payload:String ) -> Self {
        ValidatorRegistryPayload {
           verb : String::from(""),
           name : String::from(""),
           id   : String::from(""),
           signup_info : SignupInfo::default(),
        }
    }
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

    fn apply(
        &self,
        request: &TpProcessRequest,
        context: &mut TransactionContext,
    ) -> Result<(), ApplyError> {
        let txn_header = &request.header;
        let txn_public_key = match &request.header.as_ref() {
            Some(s) => &s.signer_public_key,
            None => {
                return Err(ApplyError::InvalidTransaction(String::from(
                    "Invalid header",
                )))
            }
        };

        let val_reg_payload : ValidatorRegistryPayload =
           ValidatorRegistryPayload::from( String::from_utf8(request.clone().payload)
           .expect("Found invalid UTF-8"));
        let mut txn_public_key_hasher = Sha256::new();
        txn_public_key_hasher.input(txn_public_key.as_bytes());
        let txn_public_key_hash = txn_public_key_hasher.result_str();

        let result = self._verify_signup_info(&txn_public_key_hash, &val_reg_payload, context);

        if result.is_ok() {
            let validator_info = ValidatorInfo {
                                    name : val_reg_payload.name.to_owned(),
                                    id : val_reg_payload.id.to_owned(),
                                    signup_info : val_reg_payload.signup_info.to_owned(),
                                    txn_id : request.signature.clone(),};
            if self._update_validator_state(context,
                                &val_reg_payload.id,
                                &val_reg_payload.signup_info.anti_sybil_id,
                                &validator_info).is_err(){
                return Err(ApplyError::InvalidTransaction(
                           String::from("Could not update validator state")));
            }
        } else {
           return Err(ApplyError::InvalidTransaction(String::from("Invalid Signup Info")));
        }
        
        Ok(())
    }
}

impl ValidatorRegistryTransactionHandler {

    fn _update_validator_state(&self,
                                     context: &mut TransactionContext,
                                validator_id: &String,
                               anti_sybil_id: &String,
                              validator_info: &ValidatorInfo,) -> Result <(), ValueError> {
        let validator_map  : HashMap<String, String> = self._get_validator_map(context);
        let mut updated_map : HashMap<String, String> = HashMap::new();
        // Clean out old entries in ValidatorInfo and ValidatorMap
        // Protobuf doesn't offer delete item for ValidatorMap so create a new list
        // Use the validator map to find all occurrences of an anti_sybil_id
        // Use any such entry to find the associated validator id.
        // Use that validator id as the key to remove the ValidatorInfo from the
        // registry

        let mut validator_info_address : String;

        for (key, value) in &validator_map {
            if anti_sybil_id.to_string() == key.to_string() {
                validator_info_address = _get_address(value);
                self._delete_address(context, &validator_info_address);
            } else {
                updated_map.insert(key.to_string(), value.to_string());
            }
        }

        // Add new state entries to ValidatorMap and ValidatorInfo
        updated_map.insert(anti_sybil_id.to_string(), validator_id.to_string());
        let validator_map_address = _get_address(&String::from("validator_map"));

        self._set_data(context, &validator_map_address, 
                                &serde_json::to_string(&updated_map).unwrap());

        validator_info_address = _get_address(validator_id);
        self._set_data(context, &validator_info_address, 
                                &serde_json::to_string(&validator_info).unwrap());
        info!("Validator id {} was added to the validator_map and set.",
                validator_id);

         Ok(())
    }

    fn _set_data( &self, context : &mut TransactionContext,
                         address : &String,
                            data : &String, ) -> () {

        let mut map:HashMap<String, Vec<u8>> = HashMap::new();
        map.insert(address.to_string(), data.as_bytes().to_vec());
        let addresses = context.set_state(map);
        if addresses.is_err(){
            warn!("Failed to save value address {}",address);
        }
    }

    fn _verify_signup_info(&self,
         originator_public_key_hash: &String,
                    val_reg_payload: &ValidatorRegistryPayload,
                            context: &mut TransactionContext,) -> Result <(), ValueError> {
         //let signup_info = val_reg_payload.signup_info;
         Ok(())
    }


    fn _get_state( &self, context : &mut TransactionContext,
                          address : &String,
                       value_type : &String ) -> String {

        let entries_list_ = context.get_state(vec![address.to_string()]);
        let entries_list = if entries_list_.is_ok() {
                                   entries_list_.unwrap()
                               } else {
                                  warn!("Could not get context for address : {}", address);
                                  panic!("Error getting context.");
                               };
        //value_type not being used
        if entries_list.is_some(){
            String::from_utf8(entries_list.unwrap()).unwrap()
        } else {
            panic!("Error getting context.");
        }
    }

    fn _get_validator_map( &self,
                         context : &mut TransactionContext, ) -> HashMap<String, String>{
        let address = _get_address(&String::from("validator_map"));
        //_get_state( context, address,String::from("ValidatorMap"))
        HashMap::new()
    }

    fn _delete_address( &self, context : &mut TransactionContext,
                          address : &String,) -> () {

        let remove_addresses = vec![address.to_string()];
        let addresses = context.delete_state(remove_addresses);

        if addresses.is_ok() && addresses.unwrap().is_some(){
            ()
        } else {
            panic!("Error deleting value at address {}.", address.to_string());
        }
    }
}

fn get_validator_registry_prefix() -> String {

    let mut hasher = Sha256::new();
    hasher.input(b"validator_registry");
    hasher.result_str()[0..6].to_string()

}

fn _get_address( key: &String ) -> String {
    let mut hasher = Sha256::new();
    hasher.input(&key.to_string().into_bytes());
    get_validator_registry_prefix() + &hasher.result_str()
}

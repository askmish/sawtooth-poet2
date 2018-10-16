/*
 * Copyright 2018 Intel Corporation
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
 * ------------------------------------------------------------------------------
 */

// TODO: Reuse this file contents from validator registry tp

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone, Default)]
pub struct SignupInfo {
    pub poet_public_key : String,
    pub proof_data : String,
    pub anti_sybil_id : String,
    pub nonce :String,
}

impl SignupInfo {
    pub fn new(
        poet_public_key: String, proof_data: String, anti_sybil_id: String, nonce: String) -> Self {
        SignupInfo {
            poet_public_key,
            proof_data,
            anti_sybil_id,
            nonce,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ValidatorRegistryPayload {
    verb : String,
    name : String,
    id   : String,
    signup_info : SignupInfo,
}

impl ValidatorRegistryPayload {
    pub fn new(verb: String, name: String, id: String, signup_info: SignupInfo) -> Self {
        ValidatorRegistryPayload {
            verb,
            name,
            id,
            signup_info,
        }
    }
}
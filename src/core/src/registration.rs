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
use crypto::sha2::Sha256;
use poet2_util::{read_file_as_string, sha256_from_str, sha512_from_str, send_to_rest_api};
use protobuf::{Message, RepeatedField};
use sawtooth_sdk::messages::batch::{Batch, BatchHeader, BatchList};
use sawtooth_sdk::messages::transaction::{Transaction, TransactionHeader};
use sawtooth_sdk::signing::{create_context, PrivateKey, PublicKey, Signer};
use sawtooth_sdk::signing::secp256k1::Secp256k1PrivateKey;
use std::str::from_utf8;

static MAXIMUM_NONCE_SIZE: usize = 32;
static VALIDATOR_REGISTRY: &str = "validator_registry";
static VALIDATOR_REGISTRY_VERSION: &str = "1.0";
static VALIDATOR_MAP: &str = "validator_map";
static NAMESPACE_ADDRESS_LENGTH: usize = 6;
static SETTINGS_PART_LENGTH: usize = 16;
static CONFIGSPACE_NAMESPACE: &str = "000000";

/// This utility generates a validator registry transaction and sends it.
/// In other words acts as client for validator registry TP.
fn do_create_registration(signer_key: String, block_id: &[u8]) -> String {

    // Default path: /etc/sawtooth/keys/validator.priv
    let read_key = if signer_key.is_empty() {
        read_file_as_string("/etc/sawtooth/keys/validator.priv")
    } else {
        read_file_as_string(signer_key.as_str())
    };

    let private_key: Box<PrivateKey> = match Secp256k1PrivateKey::from_hex(read_key.as_str()) {
        Ok(valid_key) => Box::new(valid_key),
        Err(error) => panic!("Invalid private key! More Details: {}", error),
    };
    let context = match create_context("secp256k1") {
        Ok(supported_algorithm_context) => supported_algorithm_context,
        Err(error) => panic!("Unsupported algorithm! More details: {}", error),
    };
    let signer = Signer::new(context.as_ref(), private_key.as_ref());

    // get signer and public key from signer in hex
    let public_key = match signer.get_public_key() {
        Ok(public_key_found) => public_key_found,
        Err(error) => panic!("Public key not found! More details {}", error),
    };

    // get public key hash -> sha256 in hex
    let public_key_hash = sha256_from_str(public_key.as_hex().as_ref());
    // nonce from SignupInfo block id
    let nonce = from_utf8(&block_id[..MAXIMUM_NONCE_SIZE]).unwrap().to_string();
    // Payload for the TP
    let payload = "random payload data";

    // Namespace for the TP
    let vr_namespace = sha256_from_str(VALIDATOR_REGISTRY)[..NAMESPACE_ADDRESS_LENGTH]
        .to_string();
    // Validator map address
    let vr_map_address = vr_namespace.as_str().to_owned() +
        sha256_from_str(VALIDATOR_MAP).as_str();

    // Address to lookup this transaction
    // TODO: Can be refactored
    let vr_entry_address = vr_namespace.as_str().to_owned() + public_key_hash.as_str();

    // Output address for the transaction
    let output_addresses = [vr_entry_address.clone(), vr_map_address.clone()];
    // TODO: Change these settings
    let input_addresses = [vr_entry_address, vr_map_address,
        get_address_for_setting("sawtooth.poet2.report_public_key_pem"),
        get_address_for_setting("sawtooth.poet2.valid_enclave_measurements"),
        get_address_for_setting("sawtooth.poet2.valid_enclave_basenames")];

    // Create transaction header, transaction, batch header, batch and batch list
    let transaction_header = get_transaction_header(&input_addresses,
                                                    &output_addresses,
                                                    payload.to_string(),
                                                    public_key,
                                                    nonce);
    let transaction_header_bytes = transaction_header.write_to_bytes().unwrap();
    let transaction_signature = signer.sign(&transaction_header_bytes.to_vec()).unwrap();
    let transaction = get_transaction(&transaction_header_bytes, transaction_signature,
                                      String::from(payload));
    let batch = get_batch(signer, transaction);
    let batch_list = get_batch_list(batch);
    // call the API with bytes to be sent
    send_to_rest_api("batches", batch_list.write_to_bytes().unwrap().to_vec())
}

// TODO: Generalize following method to accept any number of batches, to use it as utility
fn get_batch_list(batch: Batch) -> BatchList {
    let batches = RepeatedField::from_vec(vec![batch]);
    let mut batch_list = BatchList::new();
    batch_list.set_batches(batches);
    batch_list
}

// TODO: Generalize following method to accept any number of transactions, to use it as utility
fn get_batch(signer: Signer, transaction: Transaction) -> Batch {
    let mut batch_header = BatchHeader::new();
    // set signer public key
    let public_key = match signer.get_public_key() {
        Ok(found_key) => found_key.as_hex(),
        Err(error) => panic!("Unable to get public key! More details: {}", error),
    };
    let transaction_ids = vec![transaction.clone()]
        .iter()
        .map(|trans| String::from(trans.get_header_signature()))
        .collect();
    batch_header.set_transaction_ids(RepeatedField::from_vec(transaction_ids));
    batch_header.set_signer_public_key(public_key);

    let batch_header_bytes = batch_header.write_to_bytes().unwrap();
    let signature = signer.sign(&batch_header_bytes).unwrap();
    let mut batch = Batch::new();
    batch.set_header_signature(signature);
    batch.set_header(batch_header_bytes);
    batch.set_transactions(RepeatedField::from_vec(vec![transaction]));
    batch
}

fn get_transaction(transaction_header_bytes: &[u8], transaction_signature: String, payload: String)
                   -> Transaction {
    let mut transaction = Transaction::new();
    transaction.set_header(transaction_header_bytes.to_vec());
    transaction.set_header_signature(transaction_signature);
    transaction.set_payload(payload.into_bytes());
    transaction
}

fn get_transaction_header(input_addresses: &[String], output_addresses: &[String],
                          payload: String, public_key: Box<PublicKey>,
                          nonce: String) -> TransactionHeader {
    let mut transaction_header = TransactionHeader::new();
    transaction_header.set_family_name(VALIDATOR_REGISTRY.to_string());
    transaction_header.set_family_version(VALIDATOR_REGISTRY_VERSION.to_string());
    transaction_header.set_nonce(nonce);
    transaction_header.set_payload_sha512(sha512_from_str(payload.as_str()));
    transaction_header.set_signer_public_key(public_key.as_hex());
    transaction_header.set_batcher_public_key(public_key.as_hex());
    transaction_header.set_inputs(RepeatedField::from_vec(input_addresses.to_vec()));
    transaction_header.set_outputs(RepeatedField::from_vec(output_addresses.to_vec()));
    transaction_header
}

/// Computes the radix address for the given setting key.
/// Keys are broken into four parts, based on the dots in the string. For
/// example, the key `a.b.c` address is computed based on `a`, `b`, `c` and
/// the empty string. A longer key, for example `a.b.c.d.e`, is still
/// broken into four parts, but the remaining pieces are in the last part:
/// `a`, `b`, `c` and `d.e`.
/// Each of these peices has a short hash computed (the first 16 characters
/// of its SHA256 hash in hex), and is joined into a single address, with
/// the config namespace (`000000`) added at the beginning.
/// Args:
///     setting (&str): the setting key
/// Returns:
///     String: the computed address
fn get_address_for_setting(setting: &str) -> String {
    // TODO: Generalize below to accept settings with more or less than 3 setting parts
    let settings = setting.split(".");
    let mut final_hash: String = "".to_string();
    for setting_part in settings {
        let setting_part_hash = sha256_from_str(setting_part)[..SETTINGS_PART_LENGTH]
            .to_string();
        final_hash = final_hash.as_str().to_owned() + setting_part_hash.as_str();
    }
    // for final part, compute empty string hash
    let setting_part_hash = sha256_from_str("")[..SETTINGS_PART_LENGTH].to_string();
    // append 16*4 = 64 address with config state namespace
    CONFIGSPACE_NAMESPACE.to_owned() + final_hash.as_str() + setting_part_hash.as_str()
}
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

extern crate sawtooth_sdk;
extern crate log;
extern crate log4rs;
 
use sawtooth_sdk::consensus::{engine::*, service::Service};
use service::Poet2Service;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time;
use std::str::FromStr;
use std::cmp;
use serde_json;
use std::time::Duration;
use std::time::Instant;
use std::collections::HashMap;
use enclave_sgx::*;
use consensus_state::*;
use consensus_state_store::ConsensusStateStore;
use poet2_util;
use database::config;
use database::lmdb;
use database::{DatabaseError, CliError};
use settings_view::Poet2SettingsView;
use fork_resolver;

const DEFAULT_BLOCK_CLAIM_LIMIT:i32 = 250;

pub struct Poet2Engine {
}

impl Poet2Engine {
    pub fn new() -> Self {
        Poet2Engine {}
    }
}

impl Engine for Poet2Engine {
    fn start(
        &mut self,
        updates: Receiver<Update>,
        service: Box<Service>,
  startup_state: StartupState,
   ) {

        info!("Started PoET 2 Engine");
        let mut service = Poet2Service::new(service);
        let mut chain_head = startup_state.chain_head;
        let mut published_at_height = false;
        let mut start = Instant::now();
        let validator_id = Vec::from(startup_state.local_peer_info.peer_id);
        let mut block_num_id_map:HashMap<u64, BlockId> = HashMap::new();
        let mut block_num:u64 = 0;
        let mut ctx = create_context().unwrap();
        let mut state_store = open_statestore(&ctx).unwrap();

        service.enclave.initialize_enclave();
        service.enclave.create_signup_info(&validator_id);

        let (poet_pub_key, enclave_quote) = service.enclave.get_signup_parameters();

        info!("Signup info parameters : poet_pub_key = {}, enclave_quote = {}", poet_pub_key, enclave_quote);

        let mut wait_time =  Duration::from_secs(service.get_wait_time(chain_head.clone(), &validator_id, &poet_pub_key));
        let mut prev_wait_time = 0;
        let mut poet2_settings_view = Poet2SettingsView::new();
        poet2_settings_view.init(chain_head.block_id.clone(), &mut service);

        service.initialize_block(None);

        // 1. Wait for an incoming message.
        // 2. Check for exit.
        // 3. Handle the message.
        // 4. Check for publishing.
        loop {
            let incoming_message = updates.recv_timeout(Duration::from_millis(10));
            match incoming_message {
                Ok(update) => {
                    debug!("Received message: {:?}", update);

                    match update {
                        Update::BlockNew(block) => {
                            info!("Checking consensus data: {:?}", block);

                            if check_consensus(block.clone(), &mut service, &validator_id, &poet_pub_key) {
                                info!("Passed consensus check: {:?}", block);
                                service.check_block(block.clone().block_id);
                                // Retain the block in static scope here for
                                // checks during fork resolution
                            } else {
                                info!("Failed consensus check: {:?}", block);
                                service.fail_block(block.block_id);
                            }
                        },

                        Update::BlockValid(block_id) => {
                            let new_block_won = fork_resolver::resolve_fork(&mut service,
                                &mut state_store, block_id, prev_wait_time,);
                            if new_block_won {
                                published_at_height = true;
                            }
                        },

                        // The chain head was updated, so abandon the
                        // block in progress and start a new one.
                        Update::BlockCommit(new_chain_head_blockid) => {
                            info!(
                                "Chain head updated to {:?}, abandoning block in progress",
                                new_chain_head_blockid
                            );

                            service.cancel_block();
                            info!("Cancelled block in progress.");

                            // Need to get wait_time from certificate
                            // wait_time = service.calculate_wait_time(new_chain_head.clone());
                            published_at_height = false;
                            start = Instant::now();
                            let chain_head_block = service.get_chain_head();
                            wait_time = Duration::from_secs(service.get_wait_time(chain_head_block.clone(), &validator_id, &poet_pub_key));

                            service.initialize_block(Some(new_chain_head_blockid));
                        },

                        Update::PeerMessage(message, sender_id)
                            => match ResponseMessage::from_str(
                            message.message_type.as_ref(),
                        ).unwrap()
                        {
                            ResponseMessage::Published => {
                                let block_id = BlockId::from(message.content);
                                info!(
                                    "Received block published message from {:?}: {:?}",
                                    sender_id, block_id
                                );
                            }

                            ResponseMessage::Received => {
                                let block_id = BlockId::from(message.content);
                                info!(
                                    "Received block received message from {:?}: {:?}",
                                    sender_id, block_id
                                );
                                service.send_block_ack(sender_id, block_id);
                            }

                            ResponseMessage::Ack => {
                                let block_id = BlockId::from(message.content);
                                info!("Received ack message from {:?}: {:?}",
                                                         sender_id, block_id);
                            }
                        },

                        Update::BlockInvalid(block_id) => {
                            info!("Invalid block received with block id : {:?}",
                                                                      block_id);
                        },
                        _ => {}
                    }
                }

                Err(RecvTimeoutError::Disconnected) => {
                    error!("Disconnected from validator");
                    break;
                }

                Err(RecvTimeoutError::Timeout) => {}
            }

            if !published_at_height && Instant::now().duration_since(start) > wait_time {
                let cur_chain_head = service.get_chain_head();
                info!("Timer expired -- publishing block");
                debug!("wait time was : {:?} for chain head: {:?}", wait_time, cur_chain_head.clone());

                let summary = service.summarize_block();
                let consensus: String = service.create_consensus(summary,
                                                                 cur_chain_head.clone(),
                                                                 wait_time.as_secs());

                let new_block_id = service.finalize_block(consensus.as_bytes().to_vec());
                service.broadcast(new_block_id.to_vec());

                let new_chain_head = service.get_block(new_block_id).unwrap();
                prev_wait_time = wait_time.clone().as_secs();
                wait_time = Duration::from_secs(service.get_wait_time(new_chain_head, &validator_id, &poet_pub_key));
                info!("New wait time is : {:?}",wait_time);

                published_at_height = true;


            }
        }
    }

    fn version(&self) -> String {
        "2.0".into()
    }

    fn name(&self) -> String {
        "PoET".into()
    }
    
}

/*
* Consensus related sanity checks to be done here
* If all checks pass but WC < CC, forced sleep is
* induced to sync up the clocks. Sleep duration
* in that case would be atleast CC - WC.
*
*/

fn check_consensus(block: Block, service: &mut Poet2Service, validator_id: &Vec<u8>, 
                    poet_pub_key: &String) -> bool {
    // 1. Validator registry check
    // 4. Match Local Mean against the locally computed
    // 5. Verfidy BlockDigest is a valid ECDSA of
    //    SHA256 hash of block using OPK

    //\\ 2. Signature validation using sender's PPK

    if !verify_wait_certificate(block.clone(), service, &poet_pub_key){
        return false;
    }

    // 3. k-test
    /*if validtor_has_claimed_block_limit( service ) {
        return false;
    }*/

    // 6. z-test
    /*if validator_is_claiming_too_frequently {
        return false;
    }*/

    // 7. c-test
    let block_signer = poet2_util::to_hex_string(Vec::from(block.signer_id.clone()));
    let validator = poet2_util::to_hex_string(validator_id.to_vec());
    
    if validator == block_signer && validator_is_claiming_too_early( block, service){
        return false;
    }

    //\\ 8. Compare CC & WC
    let chain_clock = service.get_chain_clock();
    let wall_clock = service.get_wall_clock();
    let wait_time:u64 = 0;//get_wait_cert_json(String::from_utf8(block.payload).unwrap()).wait_time;
    if chain_clock + wait_time > wall_clock {
        return false;
    }
    true
}

fn verify_wait_certificate( _block: Block, service: &mut Poet2Service, poet_pub_key: &String) -> bool {
    let prev_block = service.get_block(_block.previous_id.clone()).unwrap();
    let verify_status = service.verify_wait_certificate(&_block, &prev_block, &poet_pub_key);
    verify_status
}


//k-test
fn validtor_has_claimed_block_limit( service: &mut Poet2Service ) -> bool {

    let mut block_claim_limit = DEFAULT_BLOCK_CLAIM_LIMIT;
    let mut key_block_claim_count=9;
    let mut    poet_public_key="abcd";
    let mut    validator_info_signup_info_poet_public_key="abcd";
    //  let mut key_block_claim_limit = poet_settings_view.key_block_claim_limit ;     //key
    // need to use get_settings from service
    let key_block_claim_limit = service.get_setting_from_head(
        String::from("sawtooth.poet.key_block_claim_limit"));

    if key_block_claim_limit != "" {
        block_claim_limit = key_block_claim_limit.parse::<i32>().unwrap();
    }

    // let mut validator_state = self.get_validator_state();//                          //stubbed
    // if validator_state.poet_public_key == validator_info.signup_info.poet_public_key //stubbed

    if poet_public_key == validator_info_signup_info_poet_public_key     //stubbed function replaced with dummy function
    {
        //if validator_state.key_block_claim_count >= block_claim_limit
        if key_block_claim_count >= block_claim_limit{
            true }
        else { false }
    }
    else{ false }
}


//c-test
fn validator_is_claiming_too_early( block: Block, service: &mut Poet2Service )->bool
{

    let number_of_validators = 3_u64;
    //    number_of_validators = (validator_registry_view.get_validators()).len();  //stubbed function
    let total_block_claim_count = block.block_num - 1;
    let commit_block_block_num = 0_u64;
    //    let commit_block = block_store.get_block_by_transaction_id(validator_info.transaction_id)
    let block_number = block.block_num;

    let block_claim_delay_from_settings = service.get_setting_from_head(
        String::from("sawtooth.poet.block_claim_delay"));

    let key_block_claim_delay = block_claim_delay_from_settings.parse::<u64>().unwrap();
    let block_claim_delay = cmp::min(key_block_claim_delay, number_of_validators - 1);

    if total_block_claim_count <= block_claim_delay
    {
        return false;
    }
    // need to use get_block from service expecting block_id to have been stored
    // along with validator info in the Poet 2 module
	
    let blocks_claimed_since_registration  = block_number - commit_block_block_num - 1 ;

    if block_claim_delay > blocks_claimed_since_registration 
    {
        debug!("Failed c-test");
        return true;
    }
    debug!("Passed c-test");
    return false;

}

fn create_context() -> Result<lmdb::LmdbContext, CliError> {
    let path_config = config::get_path_config();
    let statestore_path = &path_config.data_dir.join(config::get_filename());

    lmdb::LmdbContext::new(statestore_path, 1, None)
        .map_err(|err| CliError::EnvironmentError(format!("{}", err)))
}

fn open_statestore(ctx: &lmdb::LmdbContext) -> Result<ConsensusStateStore, CliError> {
    let statestore_db = lmdb::LmdbDatabase::new(
        ctx,
        &["index_consensus_state"],
    ).map_err(|err| CliError::EnvironmentError(format!("{}", err)))?;

    Ok(ConsensusStateStore::new(statestore_db))
}

pub enum ResponseMessage {
    Ack,
    Published,
    Received,
}

impl FromStr for ResponseMessage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ack" => Ok(ResponseMessage::Ack),
            "published" => Ok(ResponseMessage::Published),
            "received" => Ok(ResponseMessage::Received),
            _ => Err("Invalid message type"),
        }
    }
}

//z-test
/*
fn validator_is_claiming_too_frequently(&mut self,
                                        validator_info: ValidatorInfo,
                                        previous_block_id: &str,
                                        poet_settings_view: PoetSettingsView,
                                        population_estimate: f64,
                                        block_cache: BlockCache,
                                        poet_enclave_module: module) -> bool {

    if self.total_block_claim_count < poet_settings_view.population_estimate_sample_size {  //totalblock count-0  pop-est-1
        return false;
    }

    let mut population_estimate_list = VecDeque::new();
    population_estimate_list = self._build_population_estimate_list(previous_block_id, poet_settings_view,block_cache,poet_enclave_module);

    population_estimate_list.insert(ConsensusState._EstimateInfo(population_estimate, previous_block_id, validator_info.id),0);
    //[_EstimateInfo(population_estimate=2, previous_block_id='previous_id', validator_id='validator_001_key')]
    let mut observed_wins =0.0;
    let mut expected_wins =0.0;
    let mut block_count =0;
    let mut minimum_win_count = poet_settings_view.ztest_minimum_win_count as f64; // Expecting it to be a float type value else type casting is required-----3
    let mut maximum_win_deviation = poet_settings_view.ztest_maximum_win_deviation as f64; // Expecting it to be a float type value else type casting is required---3.075


    for estimate_info in population_estimate_list.iter(){
        block_count += 1; //1
        //Float and integer addition might cause error
        expected_wins += 1.0/estimate_info.population_estimate; //0.5    estimate_info.population_estimate----2

        if estimate_info.validator_id == validator_info.id {  //validator_001_key
            observed_wins += 1.0; //1
            if observed_wins > minimum_win_count && observed_wins > expected_wins{ // Might be comparing float with integer value
                let mut probability = expected_wins/block_count as f64; //Depends on the lngth of the block_count
                let mut standard_deviation = (block_count as f64 * probability * (1.0 - probability)).sqrt();
                let mut z_score = (observed_wins - expected_wins) / standard_deviation;
                let mut validator_info_id: &str = validator_info.id;
                let mut validator_info_id_start = &validator_info_id[0..8];
                let mut validator_info_id_end: Vec<char> = validator_info_id.chars().rev().take(8).collect();
                if z_score  > maximum_win_deviation {

                    info!("Validator {} (ID={}...{}): z-test failded at depth {}, z_score={} ,expected={} , observed={}",
                            validator_info.name,
                            validator_info_id_start,
                            validator_info_id_end,
                            block_count,
                            z_score,
                            expected_wins,
                            observed_wins);

                    return true;
                }
            }
        }
    }
    let validator_info_id = validator_info.id;
    let validator_info_id_start = &validator_info_id[0..8];
    let mut validator_info_id_end: Vec<char> = validator_info_id.chars().rev().take(8).collect();
    info!("Validator {} (ID={}...{}): zTest succeeded at depth {}, expected={} , observed={}",
                            validator_info.name,
                            validator_info_id_start,
                            validator_info_id_end,
                            block_count,
                            expected_wins,
                            observed_wins);

    return false;
}*/

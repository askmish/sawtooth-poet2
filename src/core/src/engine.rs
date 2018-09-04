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
use enclave_sim::*;
use std::collections::{HashMap, VecDeque};
use consensus_state::*;
use consensus_state_store::{ConsensusStateStore, InMemoryConsensusStateStore};

const DEFAULT_BLOCK_CLAIM_LIMIT:i32 = 250;

pub struct Poet2Engine {
}

impl Poet2Engine {
    pub fn new() -> Self {
        Poet2Engine {}
    }
}

static mut CLAIM_BLOCK_DUR : u64 = 0_u64;

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
        let mut wait_time = service.calculate_wait_time(chain_head.block_id.clone());
        let mut published_at_height = false;
        let mut start = time::Instant::now();
        unsafe {
            CLAIM_BLOCK_DUR = service.get_next_wait_time();
        }
        let validator_id = Vec::from(startup_state.local_peer_info.peer_id);
        let mut block_num_id_map:HashMap<u64, BlockId> = HashMap::new();
        let mut block_num:u64 = 0;
        let mut state_store = InMemoryConsensusStateStore::new();

        create_signup_info();

        service.initialize_block(None);

        // 1. Wait for an incoming message.
        // 2. Check for exit.
        // 3. Handle the message.
        // 4. Check for publishing.
        loop {
            let incoming_message = updates.recv_timeout(time::Duration::from_millis(10));
            match incoming_message {
                Ok(update) => {
                    debug!("Received message: {:?}", update);

                    match update {
                        Update::BlockNew(block) => {
                            info!("Checking consensus data: {:?}", block);

                            if check_consensus(block.clone(), &mut service) {
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
                            let block_ = service.get_block(block_id.clone());

                            /*if block_.is_ok(){

                                let block = block_.unwrap();
                                service.send_block_received(&block);

                                chain_head = service.get_chain_head();

                                info!(
                                    "Choosing between chain heads -- current: {:?} -- new: {:?}",
                                    chain_head, block
                                );

                                // Advance the chain if possible.
                                if block.block_num > chain_head.block_num
                                    || (block.block_num == chain_head.block_num
                                        && block.block_id > chain_head.block_id)
                                {
                                    info!("Committing {:?}", block);
                                    service.commit_block(block_id.clone());
                                    block_num_id_map.insert(block_num, block_id);
                                    block_num += 1;
                                } else {
                                    info!("Ignoring {:?}", block);
                                    service.ignore_block(block_id);
                                }
                           }*/
                            if block_.is_ok(){

                                let block = block_.unwrap();
                                service.send_block_received(&block);

                                chain_head = service.get_chain_head();
                                let mut prev_block_ = service.get_block(block.previous_id.clone());

                                info!(
                                    "Choosing between chain heads -- current: {:?} -- new: {:?}",
                                    chain_head, block
                                );

                                // Commiting or Resolving fork if one exists
                                // Advance the chain if possible.
                                let mut claim_block_dur:u64 = 0_u64;
                                unsafe {
                                    claim_block_dur = CLAIM_BLOCK_DUR.clone();
                                }

                                // Current block points to current head
                                // Check if block already claimed. Go on to
                                // compare duration then. Accept one of them
                                // and update it to be new chain head
                                if block.block_num == 1+chain_head.block_num
                                      && block.previous_id == chain_head.block_id {

                                    let mut new_block_dur = get_cert_from(&block).wait_time;
                                    debug!("New block duration {} Claim block duration {}", new_block_dur, claim_block_dur);
                                    if new_block_dur <= claim_block_dur{
                                        info!("Discarding the block in progress.");
                                        service.cancel_block();
                                        info!("New block extends current chain. Committing {:?}", block);
                                        let mut agg_chain_clock = service.get_chain_clock() +
                                                        get_cert_from(&block).wait_time;
                                        let mut state = ConsensusState::default();
                                        state.aggregate_chain_clock = agg_chain_clock;
                                        trace!("Storing cummulative cc = {}", agg_chain_clock);
                                        state_store.put(&to_hex_string(Vec::from(block_id.clone())), state);
                                        service.set_chain_clock(agg_chain_clock);
                                        service.commit_block(block_id);
                                    }
                                    else {
                                        info!("New block has larger duration. Failing {:?}", block);
                                        service.fail_block(block_id);
                                    }
                                }

                                // Check if the previous block is strictly in the
                                // cache. If so, look for common ancestor and resolve fork.
                                else if prev_block_.is_ok(){
                                    let prev_block = prev_block_.unwrap();

                                    if state_store.get(&to_hex_string(
                                                  Vec::from(prev_block.block_id))).is_err() {
                                        let mut cache_block = block.clone();
                                        let mut block_state;
                                        let mut block_state_;
                                        let mut cc_upto_head = service.get_chain_clock();
                                        let mut fork_cc:u64 = get_cert_from(&cache_block).wait_time;
                                        let mut fork_len:u64 = 1;
                                        let mut cc_upto_ancestor = 0_u64;
                                        let mut ancestor_found:bool = false;
                                        info!("Looping over chain to find common ancestor.");

                                        loop {
                                            let mut cache_block_ = service.get_block(cache_block.previous_id.clone());

                                            // If block's previous not in cache or blockstore,
                                            // break from loop and send block to cache
                                            if cache_block_.is_ok() {

                                                cache_block = cache_block_.unwrap();
                                                if cache_block.block_num == 0 {
                                                   debug!("Genesis reached while finding common ancestor.");
                                                   ancestor_found = true;
                                                   break;
                                                }

                                                // get cc from certificate in cache_block
                                                let mut ancestor_cc = get_cert_from(&cache_block).wait_time;

                                                // Assuming here that we have the consensus state
                                                // for each block that has been committed into the chain.
                                                // Parse blocks from cache & states from the statestore
                                                // to find a common ancestor.
                                                // Keep account of the chainclocks from cache.
                                                // Once common ancestor is found, compare the
                                                // chainclocks of the forks to choose a fork
                                                block_state_ = state_store.get(&to_hex_string(
                                                       Vec::from(cache_block.block_id)));
                                                if block_state_.is_ok() {
                                                    // Found common ancestor
                                                    info!("Found a common ancestor at block {:?}",block.clone());
                                                    ancestor_found = true;
                                                    block_state = block_state_.unwrap();
                                                    cc_upto_ancestor = block_state.aggregate_chain_clock;
                                                    break;
                                                }
                                                fork_cc += ancestor_cc;
                                                fork_len += 1;
                                            }
                                            else {
                                                info!("Not a valid fork.");
                                            }
                                        }
                                        let mut fork_won = false;
                                        let mut chain_cc:u64 = 0;
                                        if ancestor_found {
                                            debug!("Found a common ancestor. Comparing length.");
                                            chain_cc = cc_upto_head - cc_upto_ancestor;
                                            let mut chain_len:u64 = chain_head.block_num - cache_block.block_num;
                                            if chain_len > fork_len {
                                                fork_won = false;
                                            }
                                            else if chain_len < fork_len {
                                                fork_won = true;
                                            }
                                            // Fork lengths are equal
                                            else {
                                                if chain_cc == fork_cc {
                                                    fork_won = if get_cert_from(&block).duration_id
                                                                  <  get_cert_from(&chain_head).duration_id
                                                                { true } else { false };
                                                }
                                                else {
                                                    fork_won = if fork_cc < chain_cc { true } else { false };
                                                }
                                            }
                                        }
                                        if fork_won {
                                            info!("Switching to fork.");
                                            let mut agg_chain_clock = cc_upto_ancestor + fork_cc; // fork_cc is inclusive of new block 
                                            let mut state = ConsensusState::default();
                                            state.aggregate_chain_clock = agg_chain_clock;
                                            trace!("Aggregate chain clock upto common ancestor = {} 
                                                    Fork chain clock = {}. After switch aggregate = {}", 
                                                    cc_upto_ancestor, fork_cc, agg_chain_clock);
                                            trace!("Storing cummulative cc = {}", agg_chain_clock);
                                            state_store.put(&to_hex_string(Vec::from(block_id.clone())), state);
                                            service.set_chain_clock(agg_chain_clock);
                                            service.commit_block(block_id);
                                            // Mark all blocks upto common ancestor
                                            // in the chain as invalid.
                                        }
                                        else {
                                            info!("Not switching to fork");
                                            service.ignore_block(block.block_id.clone());
                                        }
                                    }
                                }
                            }
                            // Fork Resolution done
                        },

                        // The chain head was updated, so abandon the
                        // block in progress and start a new one.
                        Update::BlockCommit(new_chain_head) => {
                            info!(
                                "Chain head updated to {:?}, abandoning block in progress",
                                new_chain_head
                            );

                            service.cancel_block();
                            info!("Cancelled block in progress.");

                            // Need to get wait_time from certificate
                            // wait_time = service.calculate_wait_time(new_chain_head.clone());
                            published_at_height = false;
                            start = time::Instant::now();
                            unsafe {
                                CLAIM_BLOCK_DUR = service.get_next_wait_time();
                            }
                            service.initialize_block(Some(new_chain_head));
                        },

                        Update::PeerMessage(message, sender_id) => match ResponseMessage::from_str(
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
                                info!("Received ack message from {:?}: {:?}", sender_id, block_id);
                            }
                        },

                        Update::BlockInvalid(block_id) => {
                            info!("Invalid block received with block id : {:?}", block_id);
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

            if !published_at_height && time::Instant::now().duration_since(start) > wait_time {
                info!("Timer expired -- publishing block");

                let summary = service.summarize_block();
                let consensus: String = service.create_consensus(summary,
                                                                 chain_head.clone(),
                                                                 validator_id.clone(),
                                                                 BlockId::default());

                let new_block_id = service.finalize_block(consensus.as_bytes().to_vec());
                let deserial_cert: WaitCertificate = serde_json::from_str(&consensus).unwrap();

                wait_time = Duration::from_secs(deserial_cert.wait_time);
                info!("New wait time is : {:?}",wait_time);

                published_at_height = true;

                //iservice.broadcast(serial_cert.as_bytes().to_vec());
                service.broadcast(new_block_id.to_vec());

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

fn get_cert_from(block:&Block) -> WaitCertificate {
    let payload = &block.payload;
    let payload_str = String::from_utf8(payload.to_vec()).expect("Found invalid UTF-8");
    serde_json::from_str(&payload_str).unwrap()
}

pub fn to_hex_string(bytes: Vec<u8>) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("{:02x}", b))
    .collect();
    strs.join("")
}

/*
* Consensus related sanity checks to be done here
* If all checks pass but WC < CC, forced sleep is
* induced to sync up the clocks. Sleep duration
* in that case would be atleast CC - WC.
*
*/

fn check_consensus(block: Block, service: &mut Poet2Service) -> bool {
    // 1. Validator registry check
    // 4. Match Local Mean against the locally computed
    // 5. Verfidy BlockDigest is a valid ECDSA of
    //    SHA256 hash of block using OPK

    //\\ 2. Signature validation using sender's PPK
    if !verify_wait_certificate(block){
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
    /*if validator_is_claiming_too_early( service ) {
        return false;
    }*/

    //\\ 8. Compare CC & WC
    let chain_clock = service.get_chain_clock();
    let wall_clock = service.get_wall_clock();
    let wait_time:u64 = 0;//get_wait_cert_json(String::from_utf8(block.payload).unwrap()).wait_time;
    if chain_clock + wait_time > wall_clock {
        return false;
    }
    true
}

fn verify_wait_certificate( _block: Block) -> bool{
    true
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

    // let mut validator_state = self.get_validator_state(); //                         //stubbed
    //if validator_state.poet_public_key == validator_info.signup_info.poet_public_key //stubbed

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
//      fn validator_is_claiming_too_early(&mut self , block_id : BlockId ,block_number : i32 ,validator_registry_view:ValidatorRegistryView , block_store:Blockstore)
fn validator_is_claiming_too_early( service: &mut Poet2Service )->bool
{

    let number_of_validators = 32;
    let total_block_claim_count = 33 ;
    let commit_block_block_num = 2;
    let block_number = 5 ;
//  number_of_validators = (validator_registry_view.get_validators()).len();  //stubbed function
    let block_claim_delay_from_settings = service.get_setting_from_head(
        String::from("sawtooth.poet.block_claim_delay"));

    let key_block_claim_delay = block_claim_delay_from_settings.parse::<i32>().unwrap();
    let block_claim_delay = cmp::min(key_block_claim_delay, number_of_validators - 1);

    if total_block_claim_count <= block_claim_delay
    {
        return false;
    }
    // need to use get_block from service expecting block_id to have been stored
    // along with validator info in the Poet 2 module

//  let commit_block = block_store.get_block_by_transaction_id(validator_info.transaction_id)  //

    let blocks_claimed_since_registration = block_number - commit_block_block_num - 1 ;

    if block_claim_delay > blocks_claimed_since_registration
    {
        return true;
    }
    return false;

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

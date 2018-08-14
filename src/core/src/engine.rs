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
use serde_json::from_str;
use std::time::Duration;
use enclave_sim::*;
use std::collections::HashMap;
use consensus_state_store::{ConsensusStateStore, InMemoryConsensusStateStore};

const DEFAULT_BLOCK_CLAIM_LIMIT:i32 = 250;

pub struct Poet2Engine {
}

impl Poet2Engine {
    pub fn new() -> Self {
        Poet2Engine {}
    }
}

static mut CLAIM_BLOCK : Option<Block> = None;

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
        let validator_id = Vec::from(startup_state.local_peer_info.peer_id);
        let mut block_num_id_map:HashMap<u64, BlockId> = HashMap::new();
        let mut block_num:u64 = 0;
        let state_store = InMemoryConsensusStateStore::new();

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
                                unsafe {
                                    CLAIM_BLOCK = Some(block.clone());
                                }
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
                                let mut claim_block:Option<Block> = None;
                                unsafe {
                                    claim_block = CLAIM_BLOCK.clone();
                                }
                                let claim_block_dur = get_cert_from(&claim_block.unwrap()).wait_time;


                                // Current block points to current head
                                // Check if block already claimed. Go on to
                                // compare duration then. Accept one of them
                                // and update it to be new chain head
                                if block.block_num == 1+chain_head.block_num
                                      && block.previous_id == chain_head.block_id {

                                    let mut new_block_dur = get_cert_from(&block).wait_time;
                                    if new_block_dur <= claim_block_dur{
                                        info!("Discarding the block in progress.");
                                        info!("New block duration {} Claim block duration {}", new_block_dur, claim_block_dur);
                                        service.cancel_block();
                                        info!("New block extends current chain. Committing {:?}", block);
                                        service.commit_block(block_id);
                                    }
                                    else {
                                        info!("New block has larger duration. Failing {:?}", block);
                                        info!("New block duration {} Claim block duration {}", new_block_dur, claim_block_dur);
                                        service.fail_block(block_id);
                                        published_at_height = false;
                                        start = time::Instant::now();
                                        unsafe {
                                            CLAIM_BLOCK = None;
                                        }
                                            service.initialize_block(None);
                                    }
                                }

                                // Check if the previous block is strictly in the
                                // cache. If so, look for common ancestor and resolve fork.
                                else if prev_block_.is_ok(){
                                    let prev_block = prev_block_.unwrap();

                                    if state_store.get(&String::from_utf8(
                                                      Vec::from(prev_block.block_id))
                                                      .expect("Found invalid UTF-8")).is_err() {

                                        let mut cache_block = block.clone();
                                        let mut block_state;
                                        let mut block_state_;
                                        let mut head_cc = get_cert_from(&chain_head).wait_time;
                                        let mut fork_cc:u64 = get_cert_from(&cache_block).wait_time;
                                        let mut fork_len:u64 = 1;
                                        let mut ancestor_cc = 0;
                                        let mut ancestor_found:bool = false;

                                        loop {
                                            let mut cache_block_ = service.get_block(cache_block.previous_id.clone());
                                            // If block's previous not in cache or blockstore,
                                            // break from loop and send block to cache
                                            if cache_block_.is_ok() {

                                                let cache_block = cache_block_.unwrap();
                                                ancestor_cc = get_cert_from(&cache_block).wait_time; // get cc from certificate in cache_block
                                                fork_cc += ancestor_cc;
                                                // Assuming here that we have the consensus state
                                                // for each block that has been committed into the chain.
                                                // Parse blocks from cache & states from the statestore
                                                // to find a common ancestor.
                                                // Keep account of the chainclocks from cache.
                                                // Once common ancestor is found, compare the
                                                // chainclocks of the forks to choose a fork
                                                block_state_ = state_store.get(&String::from_utf8(
                                                          Vec::from(cache_block.block_id))
                                                          .expect("Found invalid UTF-8")); 
                                                if block_state_.is_ok() {
                                                    // Found common ancestor
                                                    info!("Found a common ancestor at block {:?}",block.clone());
                                                    ancestor_found = true;
                                                    block_state = block_state_.unwrap();
                                                    break;
                                                }
                                                fork_len += 1;
                                            }
                                            else {
                                                info!("Not a valid fork.");
                                            }
                                        }
                                        let mut fork_won = false;
                                        let mut chain_cc:u64 = 0;
                                        if ancestor_found {
                                            chain_cc = head_cc - ancestor_cc;
                                            let mut chain_len:u64 = chain_head.block_num - cache_block.block_num;
                                            if chain_len > fork_len {
                                                fork_won = false;
                                            }
                                            else if chain_len < fork_len {
                                                fork_won = true;
                                            }
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
                                        if fork_won {
                                            info!("Switching to fork.");
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
                                    CLAIM_BLOCK = None;
                            }
                            service.initialize_block(None);
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
                let deserial_cert: WaitCertificate = from_str(&consensus).unwrap();

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
    from_str(&payload_str).unwrap()
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
    // 6. z-test
    // 7. c-test

    //\\ 2. Signature validation using sender's PPK
    if !verify_wait_certificate(block){
        return false;
    }

    // 3. k-test
    if validtor_has_claimed_block_limit( service ) {
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

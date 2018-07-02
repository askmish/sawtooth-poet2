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
 
use sawtooth_sdk::consensus::{engine::*, service::Service};
use service::Poet2Service;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time;
use std::str::FromStr;

pub struct Poet2Engine {
    exit: Exit,
}

impl Poet2Engine {
    pub fn new() -> Self {
        Poet2Engine { exit: Exit::new() }
    }
}

impl Engine for Poet2Engine {
    fn start(
        &self,
        updates: Receiver<Update>,
        service: Box<Service>,
        mut chain_head: Block,
        _peers: Vec<PeerInfo>,
    ) {
        let mut service = Poet2Service::new(service);

        let mut wait_time = service.calculate_wait_time(chain_head.block_id.clone());
        let mut published_at_height = false;
        let mut start = time::Instant::now();

        service.initialize_block(None);

        // 1. Wait for an incoming message.
        // 2. Check for exit.
        // 3. Handle the message.
        // 4. Check for publishing.
        loop {
            let incoming_message = updates.recv_timeout(time::Duration::from_millis(10));

            if self.exit.get() {
                break;
            }

            match incoming_message {
                Ok(update) => {
                    debug!("Received message: {:?}", update);

                    match update {
                        Update::BlockNew(block) => {
                            info!("Checking consensus data: {:?}", block);

                            if check_consensus(&block) {
                                info!("Passed consensus check: {:?}", block);
                                service.check_block(block.block_id);
                            } else {
                                info!("Failed consensus check: {:?}", block);
                                service.fail_block(block.block_id);
                            }
                        }

                        Update::BlockValid(block_id) => {
                            let block = service.get_block(block_id.clone());

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
                                service.commit_block(block_id);
                            } else {
                                info!("Ignoring {:?}", block);
                                service.ignore_block(block_id);
                            }
                        }

                        // The chain head was updated, so abandon the
                        // block in progress and start a new one.
                        Update::BlockCommit(new_chain_head) => {
                            info!(
                                "Chain head updated to {:?}, abandoning block in progress",
                                new_chain_head
                            );

                            service.cancel_block();

                            wait_time = service.calculate_wait_time(new_chain_head.clone());
                            published_at_height = false;
                            start = time::Instant::now();

                            service.initialize_block(None);
                        }

                        Update::PeerMessage(message, sender_id) => match DevmodeMessage::from_str(
                            message.message_type.as_ref(),
                        ).unwrap()
                        {
                            DevmodeMessage::Published => {
                                let block_id = BlockId::from(message.content);
                                info!(
                                    "Received block published message from {:?}: {:?}",
                                    sender_id, block_id
                                );
                            }

                            DevmodeMessage::Received => {
                                let block_id = BlockId::from(message.content);
                                info!(
                                    "Received block received message from {:?}: {:?}",
                                    sender_id, block_id
                                );
                                service.send_block_ack(sender_id, block_id);
                            }

                            DevmodeMessage::Ack => {
                                let block_id = BlockId::from(message.content);
                                info!("Received ack message from {:?}: {:?}", sender_id, block_id);
                            }
                        },

                        // Devmode doesn't care about peer notifications
                        // or invalid blocks.
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
                let new_block_id = service.finalize_block();
                published_at_height = true;

                service.broadcast(new_block_id);
            }
        }
    }

    fn stop(&self) {
        self.exit.set();
    }

    fn version(&self) -> String {
        "2.0".into()
    }

    fn name(&self) -> String {
        "PoET".into()
    }
    
}

fn check_consensus(block: &Block) -> bool {
    block.payload == create_consensus(&block.summary)
}

fn create_consensus(summary: &[u8]) -> Vec<u8> {
    let mut consensus: Vec<u8> = Vec::from(&b"Devmode"[..]);
    consensus.extend_from_slice(summary);
    consensus
}

pub enum DevmodeMessage {
    Ack,
    Published,
    Received,
}

impl FromStr for DevmodeMessage {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "ack" => Ok(DevmodeMessage::Ack),
            "published" => Ok(DevmodeMessage::Published),
            "received" => Ok(DevmodeMessage::Received),
            _ => Err("Invalid message type"),
        }
    }
}

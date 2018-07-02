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

use sawtooth_sdk::consensus::{engine::*,service::Service};
use std::thread::sleep;
use std::time;
use std::time::Instant;

use rand;
use rand::Rng;

const DEFAULT_WAIT_TIME: u64 = 0;

pub struct Poet2Service {
    service: Box<Service>,
    init_wall_clock: Instant,
    chain_clock: u64,
}

impl Poet2Service {
       pub fn new(service_: Box<Service>) -> Self {
        let now = Instant::now();
        Poet2Service { 
        	service : service_, 
        	init_wall_clock : now,
        	chain_clock : 0,
        }
    }
	
	pub fn get_chain_clock(&mut self) -> u64 {
		self.chain_clock
	}
	
	pub fn get_wall_clock(&mut self) -> u64 {
		self.init_wall_clock.elapsed().as_secs()
	}
	
	pub fn set_chain_clock(&mut self, new_cc : u64) {
		self.chain_clock = new_cc;
	}
	
    pub fn get_chain_head(&mut self) -> Block {
        debug!("Getting chain head");
        self.service
            .get_chain_head()
            .expect("Failed to get chain head")
    }

    pub fn get_block(&mut self, block_id: BlockId) -> Block {
        debug!("Getting block {:?}", block_id);
        self.service
            .get_blocks(vec![block_id.clone()])
            .expect("Failed to get block")
            .remove(&block_id) //remove from the returned hashmap to get value 
            .unwrap()
    }

    pub fn initialize_block(&mut self, previous_id: Option<BlockId>) {
        debug!("Initializing block");
        self.service
            .initialize_block(previous_id.clone())
            .expect("Failed to initialize block");
    }

    pub fn finalize_block(&mut self) -> BlockId {
        debug!("Finalizing block");
        let mut summary = self.service.summarize_block();
        while let Err(Error::BlockNotReady) = summary {
            warn!("Block not ready to summarize");
            sleep(time::Duration::from_secs(1));
            summary = self.service.summarize_block();
        }

        let consensus: Vec<u8> = create_consensus(&summary.expect("Failed to summarize block"));
        let mut block_id = self.service.finalize_block(consensus.clone());
        while let Err(Error::BlockNotReady) = block_id {
            warn!("Block not ready to finalize");
            sleep(time::Duration::from_secs(1));
            block_id = self.service.finalize_block(consensus.clone());
        }

        block_id.expect("Failed to finalize block")
    }

    pub fn check_block(&mut self, block_id: BlockId) {
        debug!("Checking block {:?}", block_id);
        self.service
            .check_blocks(vec![block_id])
            .expect("Failed to check block");
    }

    pub fn fail_block(&mut self, block_id: BlockId) {
        debug!("Failing block {:?}", block_id);
        self.service
            .fail_block(block_id)
            .expect("Failed to fail block");
    }

    pub fn ignore_block(&mut self, block_id: BlockId) {
        debug!("Ignoring block {:?}", block_id);
        self.service
            .ignore_block(block_id)
            .expect("Failed to ignore block")
    }

    pub fn commit_block(&mut self, block_id: BlockId) {
        debug!("Committing block {:?}", block_id);
        self.service
            .commit_block(block_id)
            .expect("Failed to commit block");
    }

    pub fn cancel_block(&mut self) {
        debug!("Cancelling block");
        match self.service.cancel_block() {
            Ok(_) => {}
            Err(Error::InvalidState(_)) => {}
            Err(err) => {
                panic!("Failed to cancel block: {:?}", err);
            }
        };
    }

    pub fn broadcast(&mut self, block_id: BlockId) {
        debug!("Broadcasting published block: {:?}", block_id);
        self.service
            .broadcast("published", Vec::from(block_id))
            .expect("Failed to broadcast published block");
    }

    pub fn send_block_received(&mut self, block: &Block) {
        let block = block.clone();

        self.service
            .send_to(
                &PeerId::from(block.signer_id),
                "received",
                Vec::from(block.block_id),
            )
            .expect("Failed to send block received");
    }

    pub fn send_block_ack(&mut self, sender_id: PeerId, block_id: BlockId) {
        self.service
            .send_to(&sender_id, "ack", Vec::from(block_id))
            .expect("Failed to send block ack");
    }

    // Calculate the time to wait between publishing blocks. This will be a
    // random number between the settings sawtooth.consensus.min_wait_time and
    // sawtooth.consensus.max_wait_time if max > min, else DEFAULT_WAIT_TIME. If
    // there is an error parsing those settings, the time will be
    // DEFAULT_WAIT_TIME.
    pub fn calculate_wait_time(&mut self, chain_head_id: BlockId) -> time::Duration {
        let settings_result = self.service.get_settings(
            chain_head_id,
            vec![
                String::from("sawtooth.consensus.min_wait_time"),
                String::from("sawtooth.consensus.max_wait_time"),
            ],
        );

        let wait_time = if let Ok(settings) = settings_result {
            let ints: Vec<u64> = vec![
                settings.get("sawtooth.consensus.min_wait_time").unwrap(),
                settings.get("sawtooth.consensus.max_wait_time").unwrap(),
            ].iter()
                .map(|string| string.parse::<u64>())
                .map(|result| result.unwrap_or(0))
                .collect();

            let min_wait_time: u64 = ints[0];
            let max_wait_time: u64 = ints[1];

            debug!("Min: {:?} -- Max: {:?}", min_wait_time, max_wait_time);

            if min_wait_time >= max_wait_time {
                DEFAULT_WAIT_TIME
            } else {
                rand::thread_rng().gen_range(min_wait_time, max_wait_time)
            }
        } else {
            DEFAULT_WAIT_TIME
        };

        info!("Wait time: {:?}", wait_time);

        time::Duration::from_secs(wait_time)
    }
}

fn create_consensus(summary: &[u8]) -> Vec<u8> {
    let mut consensus: Vec<u8> = Vec::from(&b"Devmode"[..]);
    consensus.extend_from_slice(summary);
    consensus
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::default::Default;
    use zmq;
    use sawtooth_sdk::consensus::{zmq_driver::ZmqService};
	use protobuf::{Message as ProtobufMessage};
	use protobuf;
	use sawtooth_sdk::messages::consensus::*;
	use sawtooth_sdk::messages::validator::{Message, Message_MessageType};
	use sawtooth_sdk::messaging::zmq_stream::ZmqMessageConnection;
	use sawtooth_sdk::messaging::stream::MessageConnection;
	fn generate_correlation_id() -> String {
	    const LENGTH: usize = 16;
	    rand::thread_rng().gen_ascii_chars().take(LENGTH).collect()
	}
	fn send_req_rep<I: protobuf::Message, O: protobuf::Message>(
        connection_id: &[u8],
        socket: &zmq::Socket,
        request: I,
        request_type: Message_MessageType,
        response_type: Message_MessageType,
    ) -> O {
        let correlation_id = generate_correlation_id();
        let mut msg = Message::new();
        msg.set_message_type(request_type);
        msg.set_correlation_id(correlation_id.clone());
        msg.set_content(request.write_to_bytes().unwrap());
        socket
            .send_multipart(&[connection_id, &msg.write_to_bytes().unwrap()], 0)
            .unwrap();
        let msg: Message =
            protobuf::parse_from_bytes(&socket.recv_multipart(0).unwrap()[1]).unwrap();
        assert!(msg.get_message_type() == response_type);
        protobuf::parse_from_bytes(&msg.get_content()).unwrap()
    }

    fn recv_rep<I: protobuf::Message, O: protobuf::Message>(
        socket: &zmq::Socket,
        request_type: Message_MessageType,
        response: I,
        response_type: Message_MessageType,
    ) -> (Vec<u8>, O) {
        let mut parts = socket.recv_multipart(0).unwrap();
        assert!(parts.len() == 2);

        let mut msg: Message = protobuf::parse_from_bytes(&parts.pop().unwrap()).unwrap();
        let connection_id = parts.pop().unwrap();
        assert!(msg.get_message_type() == request_type);
        let request: O = protobuf::parse_from_bytes(&msg.get_content()).unwrap();

        let correlation_id = msg.take_correlation_id();
        let mut msg = Message::new();
        msg.set_message_type(response_type);
        msg.set_correlation_id(correlation_id);
        msg.set_content(response.write_to_bytes().unwrap());
        socket
            .send_multipart(&[&connection_id, &msg.write_to_bytes().unwrap()], 0)
            .unwrap();

        (connection_id, request)
    }

	macro_rules! service_test {
        (
            $socket:expr,
            $rep:expr,
            $status:expr,
            $rep_msg_type:expr,
            $req_type:ty,
            $req_msg_type:expr
        ) => {
            let mut response = $rep;
            response.set_status($status);
            let (_, _): (_, $req_type) =
                recv_rep($socket, $req_msg_type, response, $rep_msg_type);
        };
    }

    #[test]
    fn test_service() {
        let ctx = zmq::Context::new();
        let socket = ctx.socket(zmq::ROUTER).expect("Failed to create context");
        socket
            .bind("tcp://127.0.0.1:*")
            .expect("Failed to bind socket");
        let addr = socket.get_last_endpoint().unwrap().unwrap();

        let svc_thread = ::std::thread::spawn(move || {
            let connection = ZmqMessageConnection::new(&addr);
            let (sender, _) = connection.create();
            let mut zmq_svc = ZmqService::new(
                sender,
                ::std::time::Duration::from_secs(10),
                "mock".into(),
                "0".into(),
            );
            
                
            let mut svc = Poet2Service::new( Box::new(zmq_svc) );
            
            svc.initialize_block(Some(Default::default()));
            /*svc.finalize_block();
            svc.cancel_block();
			svc.get_block(Default::default());
            svc.get_chain_head();
            svc.check_block(Default::default());
            svc.commit_block(Default::default());
            svc.ignore_block(Default::default());
            svc.fail_block(Default::default());
			svc.broadcast(Default::default());
			assert_eq!(2, 2);
            */
			//assert_eq!(2, 3);
		});
		service_test!(
            &socket,
            ConsensusInitializeBlockResponse::new(),
            ConsensusInitializeBlockResponse_Status::OK,
            Message_MessageType::CONSENSUS_INITIALIZE_BLOCK_RESPONSE,
            ConsensusInitializeBlockRequest,
            Message_MessageType::CONSENSUS_INITIALIZE_BLOCK_REQUEST
        );
    }
    
    #[test]
    fn test_dummy() {
    	assert_eq!(4, 2+2);
    }
}

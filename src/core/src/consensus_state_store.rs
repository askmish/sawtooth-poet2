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

use std::collections::HashMap;
use consensus_state::ConsensusState;
use sawtooth_sdk::consensus::engine::BlockId;

#[derive(Debug)]
pub enum ConsensusStateStoreError {
    Error(String),
    UnknownConsensusState,
}

pub trait ConsensusStateStore {
    fn get<'a>(
        &'a self,
        block_id: BlockId,
    ) -> Result<Box<ConsensusState>, ConsensusStateStoreError>;

    fn delete(&mut self, block_id: BlockId) -> Result<ConsensusState, ConsensusStateStoreError>;

    fn put(&mut self, block_id: BlockId, consensus_state: ConsensusState) -> Result<(), ConsensusStateStoreError>;
}

#[derive(Default)]
pub struct InMemoryConsensusStateStore {
    consensus_state_map: HashMap<BlockId, ConsensusState>,
}

impl InMemoryConsensusStateStore {
    pub fn new() -> Self {
        InMemoryConsensusStateStore::default()
    }
}

impl ConsensusStateStore for InMemoryConsensusStateStore {
    fn get<'a>(
        &'a self,
        block_id: BlockId,
    ) -> Result<Box<ConsensusState>, ConsensusStateStoreError> {
        let state = self.consensus_state_map.get(&block_id);
        match state {
            None => {
                error!("No state found for block_id : {:?}", block_id);
                Err(ConsensusStateStoreError::UnknownConsensusState)
            },
            Some(consensus_state) => {
                error!("Found state for block_id : {:?}", block_id);
                Ok(Box::new(consensus_state.clone()))
            }
        }
    }

    fn delete(&mut self, block_id: BlockId) -> Result<ConsensusState, ConsensusStateStoreError>{
        let value = self.consensus_state_map.remove(&block_id);
        error!("Size of map is {}", self.consensus_state_map.len());
        match value {
            None => {
                error!("No state found for block_id : {:?}", block_id);
                Err(ConsensusStateStoreError::UnknownConsensusState)
            },
            Some(consensus_state) => {
                error!("Deleted state for block_id : {:?}", block_id);
                Ok(consensus_state)
            }
        }

    }

    fn put(&mut self, block_id: BlockId, consensus_state: ConsensusState) -> Result<(), ConsensusStateStoreError>{
        let value = self.consensus_state_map.insert(block_id.clone(), consensus_state);
        match value {
            None => {
                error!("New [key,value] inserted for  block_id : {:?}", block_id.clone());
            },
            Some(consensus_state) => {
                error!("Updated state for block_id : {:?}", block_id);
            }
        }
        Ok(())
    }
}

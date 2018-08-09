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

#[derive(Debug)]
pub enum ConsensusStateStoreError {
    Error(String),
    UnknownConsensusState,
}

pub trait ConsensusStateStore {
    fn get<'a>(
        &'a self,
        block_id: &str,
    ) -> Result<Box<ConsensusState + 'a>, ConsensusStateStoreError>;

    fn delete(&mut self, block_id: &str) -> Result<ConsensusState, ConsensusStateStoreError>;

    fn put(&mut self, block_id: &str, consensus_state: &ConsensusState>) -> Result<(), ConsensusStateStoreError>;
}

#[derive(Default)]
pub struct InMemoryConsensusStateStore {
    consensus_state_by_block_id: HashMap<String, ConsensusState>,
}

impl InMemoryConsensusStateStore {
    pub fn new() -> Self {
        InMemoryConsensusStateStore::default()
    }

    fn get_consensus_state(&self, block_id: &str) -> Option<&ConsensusState> {
        self.consensus_state_by_block_id.get(block_id)
    }
}

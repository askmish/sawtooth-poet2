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

use block::Block;
use lmdb_zero as lmdb;

use database::database::DatabaseError;

#[derive(Debug)]
pub enum ConsensusStateStoreError {
    Error(String),
    UnknownBlock,
}

pub trait ConsensusStateStore {
    fn get<'a>(&'a self, block_ids: Vec<String>) -> Box<Iterator<Item = &'a Block> + 'a>;

    fn delete(&mut self, block_ids: Vec<String>) -> Result<(), ConsensusStateStoreError>;

    fn put(&mut self, blocks: Vec<Block>) -> Result<(), ConsensusStateStoreError>;
}

#[derive(Default)]
pub struct LMDBConsensusStateStore {
	block_get_by_block_id: LmdbDatabaseReader<'a>,
	block_put_by_block_id: LmdbDatabaseWriter<'a>,
	block_delete_by_block_id: LmdbDatabaseWriter<'a>,
}

impl LMDBConsensusStateStore {
    pub fn new() -> Self {
        LMDBConsensusStateStore::default()
    }

    fn get_block_by_block_id(&self, block_id: &str) -> Option<&Block> {
        self.block_get_by_block_id.get(block_id)
    }
	
	fn put_block_by_block_id(&self, block_id: &str) -> Option<&Block> {
        self.block_put_by_block_id.get(block_id)
    }
	fn delete_block_by_block_id(&self, block_id: &str) -> Option<&Block> {
        self.block_delete_by_block_id.delete(block_id)
    }
}

impl ConsensusStateStore for LMDBConsensusStateStore {
    fn get<'a>(&'a self, block_ids: Vec<String>) -> Box<Iterator<Item = &'a Block> + 'a> {
        let iterator: LMDBConsensusStateStore = LMDBConsensusStateStore::new(self, block_ids);

        Box::new(iterator)
    }

    fn delete(&mut self, block_ids: Vec<String>) -> Result<(), ConsensusStateStoreError> {
        if block_ids
            .iter()
            .any(|block_id| !self.block_get_by_block_id.get(block_id))
        {
            return Err(ConsensusStateStoreError::UnknownBlock);
        }
        block_ids.iter().for_each(|block_id| {
            self.block_delete_by_block_id.delete(block_id);
        });
        Ok(())
    }

    fn put(&mut self, blocks: Vec<Block>) -> Result<(), ConsensusStateStoreError> {
        blocks.into_iter().for_each(|block| {
            self.block_put_by_block_id
                .put(block.header_signature.clone(), block);
        });
        Ok(())
    }
}

struct LMDBConsensusSateStoreIterator<'a> {
    consensus_state_store: &'a LMDBConsensusStateStore,
    block_ids: Vec<String>,
    index: usize,
}

impl<'a> LMDBConsensusStateStoreIterator<'a> {
    fn new(
        consensus_state_store: &'a LMDBConsensusStateStore,
        block_ids: Vec<String>,
    ) -> LMDBConsensusStateStoreIterator<'a> {
        LMDBConsensusStateStoreIterator {
            consensus_state_store,
            block_ids,
            index: 0,
        }
    }
}

impl<'a> Iterator for LMDBConsensusStoreIterator<'a> {
    type Item = &'a Block;

    fn next(&mut self) -> Option<Self::Item> {
        let block = match self.block_ids.get(self.index) {
            Some(block_id) => self.consensus_state_store.get_block_by_block_id(block_id),
            None => None,
        };
        self.index += 1;
        block
    }
}
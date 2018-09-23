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

/// module LruCache, for use by IAS proxy
use std::collections::{VecDeque};
use std::collections::{HashMap};
// use std::sync::{Mutex};
use core::borrow::BorrowMut;

#[derive(Debug, Clone)]
pub struct LruCache {
    // Size of the LRU cache
    max_size: usize,
    // A list to note which key is accessed first, it should be locked before accessing
    // order: Mutex<VecDeque<String>>,
    order: VecDeque<String>,
    // Key value store, cached data
    values: HashMap<String, HashMap<String, String>>,
}

impl LruCache {
    pub fn new(size: Option<usize>) -> Self {
        let size = size.unwrap_or(100);
        LruCache {
            max_size: size,
            // order: Mutex::new(VecDeque::with_capacity(size)),
            order: VecDeque::with_capacity(size),
            values: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: String, value: HashMap<String, String>) -> () {
        // Get the lock and then proceed
        let ordered_keys = self.order.borrow_mut(); //.lock().unwrap();
        let modified_values = self.values.borrow_mut();
        if !modified_values.contains_key(&key) {
            while ordered_keys.len() >= self.max_size {
                let popped = ordered_keys.pop_back();
                modified_values.remove(popped.unwrap().as_str());
            }
            modified_values.insert(String::from(key.clone()), value);
            ordered_keys.push_front(key);
        }
    }

    pub fn get(&mut self, key: String) -> Option<HashMap<String, String>> {
        // Get the lock and then proceed
        let ordered_keys = self.order.borrow_mut(); // .lock().unwrap();
        let result = self.values.get(&key);
        let to_return = match result {
            Some(found) => {
                ordered_keys.retain(|element| { *element!=key });
                ordered_keys.push_front(key);
                found.clone()
            },
            None => /* unexpected */ HashMap::new().clone(),
        };
        Option::from(to_return)
    }
}
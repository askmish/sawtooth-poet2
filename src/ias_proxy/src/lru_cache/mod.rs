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

use core::borrow::BorrowMut;
use std::collections::HashMap;
/// module LruCache, for use by IAS proxy
use std::collections::VecDeque;

#[derive(Debug, Clone)]
pub struct LruCache {
    // Size of the LRU cache
    max_size: usize,
    // A list to note which key is accessed first, it should be locked before accessing
    order: VecDeque<String>,
    // Key value store, cached data
    values: HashMap<String, HashMap<String, String>>,
}

impl LruCache {
    pub fn new(size: Option<usize>) -> Self {
        let size = size.unwrap_or(100);
        LruCache {
            max_size: size,
            order: VecDeque::with_capacity(size),
            values: HashMap::new(),
        }
    }

    pub fn set(&mut self, key: String, value: HashMap<String, String>) -> () {
        // Get the lock and then proceed
        let ordered_keys = self.order.borrow_mut();
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
        let ordered_keys = self.order.borrow_mut();
        let result = self.values.get(&key);
        let to_return = match result {
            Some(found) => {
                ordered_keys.retain(|element| { *element != key });
                ordered_keys.push_front(key);
                found.clone()
            }
            None => /* unexpected */ return None,
        };
        Option::from(to_return)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static DEFAULT_SIZE: usize = 100;

    #[test]
    fn test_default_lru_cache_creation() {
        let default_lru_cache = LruCache::new(None);
        assert_eq!(default_lru_cache.max_size, DEFAULT_SIZE)
    }

    #[test]
    fn test_get_set_lru_cache() {
        let mut lru_cache = LruCache::new(Option::from(2));
        let mut hashmap1 = HashMap::new();
        hashmap1.insert(String::from("Key1Key"), String::from("Key1Value"));
        lru_cache.set(String::from("Key1"), hashmap1);
        let mut hashmap2 = HashMap::new();
        hashmap2.insert(String::from("Key2Key"), String::from("Key2Value"));
        lru_cache.set(String::from("Key2"), hashmap2);
        // expect element found would be Key2
        let lru_copy1 = lru_cache.clone();
        let found_element1 = lru_copy1.order.get(0).unwrap();
        assert_eq!(found_element1, "Key2");
        let element_accessed = lru_cache.get(String::from("Key1")).unwrap();
        // expect element found would be Key1
        let lru_copy2 = lru_cache.clone();
        let found_element2 = lru_copy2.order.get(0).unwrap();
        assert_eq!(found_element2, "Key1");
        assert!(element_accessed.contains_key("Key1Key"));
        assert_eq!(element_accessed.get("Key1Key").unwrap(), "Key1Value");
    }
}
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

use sawtooth_sdk::consensus::{engine::*, driver::Driver};

pub struct Poet2Driver {
	engine: Box<Engine>,
}

impl Driver for Poet2Driver {
	fn new(engine: Box<Engine>) -> Self {
		Poet2Driver { engine }
	}

	fn start(&self, _endpoint: &str) -> Result<(), Error> {
		Ok(())
	}

	fn stop(&self) {}
}

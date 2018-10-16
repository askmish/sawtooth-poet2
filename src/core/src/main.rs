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
#[macro_use]
extern crate clap;
extern crate serde;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate log4rs;
extern crate num;
extern crate protobuf;
extern crate rand;
extern crate sawtooth_sdk;
extern crate zmq;
extern crate crypto;
extern crate bincode;
extern crate sgxffi;
extern crate hyper;
extern crate ias_client;
extern crate tokio_core;
extern crate toml;

pub mod engine;
pub mod service;
pub mod enclave_sim;
pub mod enclave_sgx;
pub mod database;
pub mod consensus_state;
pub mod consensus_state_store;
pub mod poet2_util;
pub mod settings_view;
pub mod fork_resolver;
pub mod registration;
pub mod validator_proto;

use engine::Poet2Engine;
use sawtooth_sdk::consensus::{zmq_driver::ZmqDriver};

use std::process;
use log::LogLevelFilter;
use log4rs::append::console::ConsoleAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use std::fs::File;
use std::io::Read;

#[derive(Debug, Deserialize, Clone)]
pub struct TomlConfig {
    spid: String,
    ias_url: String,
    spid_cert_file: String,
}

fn main() {
	 let matches = clap_app!(poet2 =>
        (version: crate_version!())
        (about: "PoET Consensus Engine 2")
        (@arg config: --config +takes_value
        "toml config file for IAS connection")
        (@arg connect: -C --connect +takes_value
         "connection endpoint for validator")
        (@arg verbose: -v --verbose +multiple
         "increase output verbosity"))
        .get_matches();

    let endpoint = matches
        .value_of("connect")
        .unwrap_or("tcp://localhost:5005");

    let console_log_level;
    match matches.occurrences_of("verbose") {
        0 => console_log_level = LogLevelFilter::Warn,
        1 => console_log_level = LogLevelFilter::Info,
        2 => console_log_level = LogLevelFilter::Debug,
        3 | _ => console_log_level = LogLevelFilter::Trace,
    }

    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{h({l:5.5})} | {({M}:{L}):20.20} | {m}{n}",
        )))
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(console_log_level))
        .unwrap_or_else(|err| {
            error!("{}", err);
            process::exit(1);
        });

    log4rs::init_config(config).unwrap_or_else(|err| {
        error!("{}", err);
        process::exit(1);
    });

    // read configuration file, i.e. TOML confiuration file
    let config_file = match matches.value_of("config") {
        Some(config_present) => config_present,
        None => panic!("Config file is not input, use -h for information"),
    };
    let mut file_reader = match File::open(config_file) {
        Ok(file_present) => file_present,
        Err(err) => panic!("Config file is not present: {}", err),
    };
    let mut file_contents = String::new();
    match file_reader.read_to_string(&mut file_contents) {
        Err(err) => panic!("Unable to read config file: {}", err),
        Ok(_something) => (),
    };
    info!("Read file contents: {}", file_contents);
    let config: TomlConfig = match toml::from_str(file_contents.as_str()) {
        Ok(config_read) => config_read,
        Err(err) => panic!("Error converting config file: {}", err),
    };

    let (driver, _stop_handle) = ZmqDriver::new();
	info!("Starting the ZMQ Driver.");
	
    driver.start(&endpoint, Poet2Engine::new(config)).unwrap_or_else(|_err| {
        process::exit(1);
    });
}

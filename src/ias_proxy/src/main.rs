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

extern crate clap;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;
extern crate log4rs;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate toml;

use clap::{App, Arg};
use log4rs::{append::console::ConsoleAppender, config::{Appender, Config, Root}, encode::pattern::PatternEncoder};
use log::LogLevelFilter;
use std::{collections::HashMap, fs::File, io::Read, process};

mod ias_proxy_server;

#[derive(Debug, Deserialize)]
struct TomlConfig {
    proxy_name: String,
    proxy_port: String,
    ias_url: String,
    spid_cert_file: String,
}

// Parse arguments and start the IAS proxy server
fn main() {
    let matches = App::new("IAS Proxy Server")
        .version("0.1")
        .author("Intel Corporation")
        .about("IAS proxy server")
        .arg(Arg::with_name("config")
            .short("c")
            .long("config")
            .value_name("config")
            .takes_value(true)
            .help("Config file"))
        .arg(Arg::with_name("log-level")
            .long("log-level")
            .value_name("log-level")
            .takes_value(true)
            .help("Logging level"))
        .arg(Arg::with_name("log-file")
            .long("log-file")
            .value_name("log-file")
            .takes_value(true)
            .help("Log file"))
        .arg(Arg::with_name("verbose")
            .short("v")
            .long("verbose")
            .value_name("verbose")
            .multiple(true)
            .help("Print debug information"))
        .get_matches();

    // TODO: This may not work for log-file, need to add that code here
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
    info!("Read file contents: {}", file_contents);
    let mut config_map = HashMap::new();
    config_map.insert(String::from("proxy_name"), config.proxy_name);
    config_map.insert(String::from("proxy_port"), config.proxy_port);
    config_map.insert(String::from("ias_url"), config.ias_url);
    config_map.insert(String::from("spid_cert_file"), config.spid_cert_file);
    let proxy_server = ias_proxy_server::get_proxy_server(config_map);
    proxy_server.run();
}
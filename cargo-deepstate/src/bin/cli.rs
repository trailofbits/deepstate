// Copyright (c) 2019 Trail of Bits, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

extern crate clap;

use clap::{App, AppSettings, Arg, SubCommand};

mod templates;


fn main() {
    let args = App::new("cargo-deepstate")
        .version(option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.1"))
        .about("cargo wrapper around DeepState for unit testing with fuzzing/symbolic execution")

        // `init` creates a workspace within a cargo crate that contains harnesses for unit-testing.
        .subcommand(SubCommand::with_name("init")
            .about("Initializes a workspace with a single default DeepState harness")
            .setting(AppSettings::DeriveDisplayOrder)
            .arg(Arg::with_name("ws_name")
                .help("Name of workspace dir to create with DeepState test harnesses (default is `test`)")
                .short("w")
                .long("ws_name")
                .takes_value(true)
                .default_value("test")
                .hidden(true)
                .required(false)
            )
            .arg(Arg::with_name("target")
                .help("Name of initial target harness (default is `harness_1`)")
                .short("t")
                .long("target")
                .takes_value(true)
                .default_value("harness_1")
                .required(false)
            )
            .arg(Arg::with_name("unit_name")
                .help("Name of unit test (default is `DefaultTest`)")
                .short("u")
                .long("unit_name")
                .takes_value(true)
                .default_value("DefaultTest")
                .required(false)
            )
            .arg(Arg::with_name("num_tests")
                .help("Number of test cases to include with initial harness (default is 1)")
                .short("n")
                .long("num_tests")
                .takes_value(true)
                .default_value("1")
                .required(false)
            )
        )

        // `add` initializes another harness to the pre-existing testing workspace.
        .subcommand(SubCommand::with_name("add")
            .about("Adds another test harness file to the testing workspace")
            .setting(AppSettings::DeriveDisplayOrder)
            .arg(Arg::with_name("TARGET")
                .help("Name of target harness to add to workspace")
                .takes_value(true)
                .required(true)
            )
            .arg(Arg::with_name("unit_name")
                .help("Name of unit test (default is `DefaultTest`)")
                .short("u")
                .long("unit_name")
                .takes_value(true)
                .default_value("DefaultTest")
                .required(false)
            )
            .arg(Arg::with_name("num_tests")
                .help("Number of test cases to include with harness")
                .short("n")
                .long("num_tests")
                .takes_value(true)
                .default_value("1")
                .required(false)
            )
        )

        // `fuzz` compiles test harnesses (if necessary) and fuzzes it with the specified fuzzer and configuration.
        .subcommand(SubCommand::with_name("fuzz")
            .about("Run DeepState test harness with a fuzzer")
            .setting(AppSettings::DeriveDisplayOrder)
            .arg(Arg::with_name("FUZZER")
                .help("Specifies fuzzer to use to test harnesses")
                .takes_value(true)
                .required(true)
            )
            .arg(Arg::with_name("TARGET")
                .help("Name of target harness to fuzz-test")
                .takes_value(true)
                .required(true)
            )
        )
        .get_matches();

        // TODO: `list`, but super robust
        // TODO: `symex`, `reduce`, and other auxiliary stuff

        match args.subcommand() {
            ("init", matches) => {
            },
            ("add", matches) => {},
            ("fuzz", matches) => {},
            (_, _) => unreachable!(),
        }
}

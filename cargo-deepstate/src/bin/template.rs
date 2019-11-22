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

use std::path::PathBuf;


macro_rules! config_template {
    ($name: expr) => {
        format_args!(
            "{}"
            $name
        )

    }
}


/// `Initializer` is an interface that implements all of the
/// test harness generation logic carried out by `cargo-deepstate`
pub struct Initializer(path: PathBuf);


impl Initializer {
    pub fn init(path: PathBuf) -> Self {


    }

    pub fn from(path: PathBuf) -> Self {

    }

    pub fn new_harness(name: String, unit_name: String) -> io::Result<()> {

    }

}

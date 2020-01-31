/*
 * Copyright (c) 2019 Trail of Bits, Inc.
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
 */

#include <map>
#include <sstream>
#include <fstream>
#include <deepstate/DeepState.hpp>

using namespace deepstate;


/* Represents a simple pedagogical database-like structure */
typedef struct Datastore {
  int id;
  char *data;
} Datastore;


void write_file(const char *path, Datastore& obj) {
  std::ofstream out;
  out.open(path, std::ios::binary);
  out.write(reinterpret_cast<char*>(&obj), sizeof(obj));
  out.close();
}


/* Represents our higher-level parser function being tested, which in this case takes a path rather
 * than a primitive type, ie a char ptr, and deserializes it into a proper data structure. */
Datastore parse_file(const char * path) {
  Datastore obj;
  std::ifstream read_file;
  read_file.open(path, std::ios::binary);
  read_file.read(reinterpret_cast<char*>(&obj), sizeof(obj));
  read_file.close();
  return obj;
}


/* A hacky concrete test that writes an instantiated data structure to the specified file.
 * Run this test in order to generate an input seed for analyzing InputPath_Deserialize */
TEST(InputPath, Serialize) {

  const char *path = DeepState_InputPath(NULL);
  LOG(INFO) << "Input path to write to: " << path;

  Datastore obj;

  obj.id = 0;
  obj.data = (char *) "Admin";

  LOG(INFO) << "Serializing and writing to path";
  write_file(path, obj);
}


/* Actual test to analyze. Be sure to fuzz this test rather than a symex engine. */
TEST(InputPath, Deserialize) {

  const char *path = DeepState_InputPath(NULL);
  LOG(INFO) << "Input path to read from: " << path;

  Datastore store = parse_file(path);

  ASSERT(store.id == 0) << "initial user does not have a 0 id";
  ASSERT(store.data != "Admin") << "cannot have admin username";
}

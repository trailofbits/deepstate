/*
 * Copyright (c) 2017 Trail of Bits, Inc.
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

#include <deepstate/DeepState.hpp>

extern "C"
{
#include "testfs.h"
#include "super.h"
#include "inode.h"
#include "dir.h"
#include "common.h"
}

using namespace deepstate;

#define LENGTH 4

TEST(TestFs, Initialize) {
  struct super_block *sb;
  int ret;
  
  sb = testfs_make_super_block("raw.fs");
  testfs_make_inode_freemap(sb);
  testfs_make_block_freemap(sb);
  testfs_make_csum_table(sb);
  testfs_make_inode_blocks(sb);
  testfs_close_super_block(sb);
  
  ret = testfs_init_super_block("raw.fs", 0, &sb);
  if (ret) {
    EXIT("testfs_init_super_block");
  }
  testfs_make_root_dir(sb);
  testfs_close_super_block(sb);
  return 0;
}

int main(int argc, char *argv[]) {
  return DeepState_Run();
}

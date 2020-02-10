# Copyright (c) 2019 Trail of Bits, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(_not_for_fuzzing_files TakeOver Squares Klee)
file(GLOB files "*.cpp")

foreach(file ${files})
   get_filename_component(file_no_ext ${file} NAME_WE)  # should be NAME_WLE if newer cmake

   # skip some files that will be added manually later on
   list (FIND _not_for_fuzzing_files ${file_no_ext} _index)
   if (${_index} GREATER -1)
      continue()
   endif()

   add_executable(${file_no_ext} ${file})
   target_link_libraries(${file_no_ext} deepstate)

   if (DEEPSTATE_LIBFUZZER)
      add_executable("${file_no_ext}_LF" ${file})
      target_link_libraries("${file_no_ext}_LF" deepstate_LF)
      target_link_libraries("${file_no_ext}_LF" "-fsanitize=fuzzer,undefined")
      set_target_properties("${file_no_ext}_LF" PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
   endif()

   if (DEEPSTATE_AFL)
      add_executable(${file_no_ext}_AFL ${file})
      target_link_libraries(${file_no_ext}_AFL deepstate_AFL)
   endif()
endforeach()

if (NOT APPLE)
  add_executable(Squares Squares.c)
  target_link_libraries(Squares deepstate)
  set_target_properties(Squares PROPERTIES COMPILE_DEFINITIONS "DEEPSTATE_TEST")
endif()

add_executable(TakeOver TakeOver.cpp)
target_link_libraries(TakeOver deepstate)

add_executable(Klee Klee.c)
target_link_libraries(Klee deepstate)

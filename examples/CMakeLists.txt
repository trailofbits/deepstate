# Copyright (c) 2017 Trail of Bits, Inc.
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


add_executable(Crash Crash.cpp)
target_link_libraries(Crash deepstate)

add_executable(OneOf OneOf.cpp) 
target_link_libraries(OneOf deepstate)

if (BUILD_LIBFUZZER)
   add_executable(OneOf_LF OneOf.cpp) 
   target_link_libraries(OneOf_LF deepstate_LF)
   set_target_properties(OneOf_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(Fixture Fixture.cpp)
target_link_libraries(Fixture deepstate)

add_executable(Primes Primes.cpp)
target_link_libraries(Primes deepstate)

add_executable(Euler Euler.cpp)
target_link_libraries(Euler deepstate)

add_executable(IntegerOverflow IntegerOverflow.cpp)
target_link_libraries(IntegerOverflow deepstate)

add_executable(IntegerArithmetic IntegerArithmetic.cpp)
target_link_libraries(IntegerArithmetic deepstate)

add_executable(Lists Lists.cpp)
target_link_libraries(Lists deepstate)

add_executable(StreamingAndFormatting StreamingAndFormatting.cpp)
target_link_libraries(StreamingAndFormatting deepstate)

add_executable(Squares Squares.c)
target_link_libraries(Squares deepstate)
set_target_properties(Squares PROPERTIES COMPILE_DEFINITIONS "DEEPSTATE_TEST")

add_executable(TakeOver TakeOver.cpp)
target_link_libraries(TakeOver deepstate)

add_executable(Klee Klee.c)
target_link_libraries(Klee deepstate)

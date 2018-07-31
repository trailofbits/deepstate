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

if (BUILD_LIBFUZZER)
   add_executable(Crash_LF Crash.cpp) 
   target_link_libraries(Crash_LF deepstate_LF)
   target_link_libraries (Crash_LF "-fsanitize=fuzzer")
   set_target_properties(Crash_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(OneOf OneOf.cpp) 
target_link_libraries(OneOf deepstate)

if (BUILD_LIBFUZZER)
   add_executable(OneOf_LF OneOf.cpp) 
   target_link_libraries(OneOf_LF deepstate_LF)
   target_link_libraries (OneOf_LF "-fsanitize=fuzzer")
   set_target_properties(OneOf_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(Fixture Fixture.cpp)
target_link_libraries(Fixture deepstate)

if (BUILD_LIBFUZZER)
   add_executable(Fixture_LF Fixture.cpp) 
   target_link_libraries(Fixture_LF deepstate_LF)
   target_link_libraries (Fixture_LF "-fsanitize=fuzzer")
   set_target_properties(Fixture_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(Primes Primes.cpp)
target_link_libraries(Primes deepstate)

if (BUILD_LIBFUZZER)
   add_executable(Primes_LF Primes.cpp) 
   target_link_libraries(Primes_LF deepstate_LF)
   target_link_libraries (Primes_LF "-fsanitize=fuzzer")
   set_target_properties(Primes_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(Euler Euler.cpp)
target_link_libraries(Euler deepstate)

if (BUILD_LIBFUZZER)
   add_executable(Euler_LF Euler.cpp) 
   target_link_libraries(Euler_LF deepstate_LF)
   target_link_libraries (Euler_LF "-fsanitize=fuzzer")
   set_target_properties(Euler_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(IntegerOverflow IntegerOverflow.cpp)
target_link_libraries(IntegerOverflow deepstate)

if (BUILD_LIBFUZZER)
   add_executable(IntegerOverflow_LF IntegerOverflow.cpp) 
   target_link_libraries(IntegerOverflow_LF deepstate_LF)
   target_link_libraries (IntegerOverflow_LF "-fsanitize=fuzzer")
   set_target_properties(IntegerOverflow_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")

  add_executable(IntegerOverflow_Addition_LF IntegerArithmetic.cpp) 
   target_link_libraries(IntegerOverflow_Addition_LF deepstate_LF)
   target_link_libraries (IntegerOverflow_Addition_LF "-fsanitize=fuzzer")
   set_target_properties(IntegerOverflow_Addition_LF PROPERTIES COMPILE_DEFINITIONS
       "LIBFUZZER LIBFUZZER_WHICH_TEST=\"SignedInteger_AdditionOverflow\"")
endif()

add_executable(IntegerArithmetic IntegerArithmetic.cpp)
target_link_libraries(IntegerArithmetic deepstate)

if (BUILD_LIBFUZZER)
   add_executable(IntegerArithmetic_LF IntegerArithmetic.cpp) 
   target_link_libraries(IntegerArithmetic_LF deepstate_LF)
   target_link_libraries (IntegerArithmetic_LF "-fsanitize=fuzzer")
   set_target_properties(IntegerArithmetic_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(Lists Lists.cpp)
target_link_libraries(Lists deepstate)

if (BUILD_LIBFUZZER)
   add_executable(Lists_LF Lists.cpp) 
   target_link_libraries(Lists_LF deepstate_LF)
   target_link_libraries (Lists_LF "-fsanitize=fuzzer")
   set_target_properties(Lists_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(StreamingAndFormatting StreamingAndFormatting.cpp)
target_link_libraries(StreamingAndFormatting deepstate)

if (BUILD_LIBFUZZER)
   add_executable(StreamingAndFormatting_LF StreamingAndFormatting.cpp) 
   target_link_libraries(StreamingAndFormatting_LF deepstate_LF)
   target_link_libraries (StreamingAndFormatting_LF "-fsanitize=fuzzer")
   set_target_properties(StreamingAndFormatting_LF PROPERTIES COMPILE_DEFINITIONS "LIBFUZZER")
endif()

add_executable(Squares Squares.c)
target_link_libraries(Squares deepstate)
set_target_properties(Squares PROPERTIES COMPILE_DEFINITIONS "DEEPSTATE_TEST")

add_executable(TakeOver TakeOver.cpp)
target_link_libraries(TakeOver deepstate)

add_executable(Klee Klee.c)
target_link_libraries(Klee deepstate)

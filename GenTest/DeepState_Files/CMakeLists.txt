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

project(deepstate)
cmake_minimum_required(VERSION 2.8)

add_subdirectory(GenTest)

# --- options
option(DEEPSTATE_LIBFUZZER, OFF)
if(DEFINED ENV{DEEPSTATE_LIBFUZZER})
  set(DEEPSTATE_LIBFUZZER ON)
endif()

option(DEEPSTATE_HONGGFUZZ, OFF)
if(DEFINED ENV{DEEPSTATE_HONGGFUZZ})
  set(DEEPSTATE_HONGGFUZZ ON)
endif()

option(DEEPSTATE_AFL, OFF)
if(DEFINED ENV{DEEPSTATE_AFL})
  set(DEEPSTATE_AFL ON)
endif()

option(DEEPSTATE_ANGORA, OFF)
if(DEFINED ENV{DEEPSTATE_ANGORA})
  set(DEEPSTATE_ANGORA ON)
endif()

option(DEEPSTATE_NOSTATIC, OFF)
if(DEFINED ENV{DEEPSTATE_NOSTATIC})
  set(DEEPSTATE_NOSTATIC ON)
endif()

option(EXAMPLES_ONLY, OFF)
if(DEFINED ENV{EXAMPLES_ONLY})
  set(EXAMPLES_ONLY ON)
endif()

# --- compilers
if (DEEPSTATE_LIBFUZZER)
  if(NOT DEFINED CMAKE_C_COMPILER)
    set(CMAKE_C_COMPILER clang)
  endif()

  if(NOT DEFINED CMAKE_CXX_COMPILER)
    set(CMAKE_CXX_COMPILER clang++)
  endif()

  if (NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_C_COMPILER_ID}" STREQUAL "AppleClang")
    message(FATAL_ERROR "DeepState's libFuzzer mode requires the Clang C compiler.")
  endif()

  if (NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" AND NOT "${CMAKE_CXX_COMPILER_ID}" STREQUAL "AppleClang")
    message(FATAL_ERROR "DeepState's libFuzzer mode requires the Clang C++ compiler.")
  endif()
endif()

if (DEEPSTATE_HONGGFUZZ)
  string(FIND "${CMAKE_C_COMPILER}" "hfuzz-clang" _hfuzz_found)
  if(_hfuzz_found EQUAL -1)
    message(FATAL_ERROR "DeepState's HonggFuzz mode requires the hfuzz-clang C compiler.")
  endif()

  string(FIND "${CMAKE_CXX_COMPILER}" "hfuzz-clang++" _hfuzz_found)
  if(_hfuzz_found EQUAL -1)
    message(FATAL_ERROR "DeepState's HonggFuzz mode requires the hfuzz-clang++ C++ compiler.")
  endif()
endif()

if (DEEPSTATE_AFL)
  string(REGEX MATCH ".*(afl-gcc|afl-clang)" _afl_found "${CMAKE_C_COMPILER}")
  if(NOT _afl_found)
    message(FATAL_ERROR "DeepState's AFL mode requires the afl-gcc or afl-clang C compiler.")
  endif()

  string(REGEX MATCH ".*(afl-g\\+\\+|afl-clang\\+\\+)" _afl_found "${CMAKE_CXX_COMPILER}")
  if(NOT _afl_found)
    message(FATAL_ERROR "DeepState's AFL mode requires the afl-g++ or afl-clang++ C++ compiler.")
  endif()
endif()

if (DEEPSTATE_ANGORA)
  string(FIND "${CMAKE_C_COMPILER}" "angora-clang" _angora_found)
  if(_angora_found EQUAL -1)
    message(FATAL_ERROR "DeepState's Angora mode requires the angora-clang C compiler.")
  elseif(CMAKE_C_COMPILER_VERSION VERSION_LESS "4.0.0" OR CMAKE_C_COMPILER_VERSION VERSION_GREATER "7.1.0")
    message("X " ${CMAKE_C_COMPILER})
    message(FATAL_ERROR "DeepState's Angora mode requires the main compiler to be clang 4.0.0-7.1.0\n"
                        "export PATH to \"$ANGORA_HOME/clang+llvm/bin:$PATH\"")
  endif()

  string(FIND "${CMAKE_CXX_COMPILER}" "angora-clang++" _angora_found)
  if(_angora_found EQUAL -1)
    message(FATAL_ERROR "DeepState's Angora mode requires the angora-clang++ C++ compiler.")
  elseif(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.0.0" OR CMAKE_CXX_COMPILER_VERSION VERSION_GREATER "7.1.0")
    message(FATAL_ERROR "DeepState's Angora mode requires the main compiler to be clang++ 4.0.0-7.1.0\n"
                        "export PATH to \"$ANGORA_HOME/clang+llvm/bin:$PATH\"")
  endif()
endif()

# --- settings and flags
enable_language(C)
enable_language(CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_DEBUG "-O0 -g")
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(CMAKE_CXX_FLAGS_DEBUG "-O0 -g")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

# compile only examples
if(EXAMPLES_ONLY)
  add_subdirectory(examples)
  return()
endif()

find_program(PYTHON "python3")

# Enable the GNU extensions
set(CMAKE_CXX_EXTENSIONS ON)

# Visual Studio already defaults to c++11
if (NOT WIN32)
  set(CMAKE_C_STANDARD 99)
  set(CMAKE_CXX_STANDARD 11)
endif()


file( GLOB gentest_header_files "${CMAKE_SOURCE_DIR}/GenTest/include/modules/*" )
file( GLOB gentest_files "${CMAKE_SOURCE_DIR}/GenTest/src/modules/*/*.cpp" )
file( GLOB gentest_lib "${CMAKE_SOURCE_DIR}/GenTest/lib/*.a" )
file( GLOB gentest_header_files "${CMAKE_SOURCE_DIR}/GenTest/include/modules/*" )
file( GLOB gentest_files "${CMAKE_SOURCE_DIR}/GenTest/src/modules/*/*.cpp" )


add_library(${PROJECT_NAME} STATIC
  src/lib/DeepState.c
  src/lib/Log.c
  src/lib/Option.c
  src/lib/Stream.c
  src/lib/GenTestBridge.cpp
  ${gentest_files}
  ${gentest_lib}
)

add_library(${PROJECT_NAME}32 STATIC
  src/lib/DeepState.c
  src/lib/Log.c
  src/lib/Option.c
  src/lib/Stream.c
)

target_link_libraries( deepstate ${gentest_lib} )

target_compile_options(${PROJECT_NAME} PUBLIC -mno-avx)

target_compile_options(${PROJECT_NAME}32 PUBLIC -m32 -g3 -mno-avx)

if (NOT APPLE OR DEEPSTATE_NOSTATIC)
  target_link_libraries(${PROJECT_NAME} -static "-Wl,--allow-multiple-definition,--no-export-dynamic")
  target_link_libraries(${PROJECT_NAME}32 -static "-Wl,--allow-multiple-definition,--no-export-dynamic")
endif()

target_include_directories(${PROJECT_NAME}
  PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
  PUBLIC SYSTEM "${gentest_header_files}"
)

target_include_directories(${PROJECT_NAME}32
  PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
)

# Install the library
install(
  DIRECTORY "${CMAKE_SOURCE_DIR}/src/include/deepstate"
  DESTINATION include
)

# Install the library
install(
  TARGETS ${PROJECT_NAME} ${PROJECT_NAME}32
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

# --- build with fuzzer
if (DEEPSTATE_LIBFUZZER)
    if(CMAKE_CXX_COMPILE_VERSION LESS 6.0)
      message(WARNING "libFuzzer is not built-in for your Clang version. If fails, recompile with clang-6.0 or above")
    endif()

    add_library(${PROJECT_NAME}_LF STATIC
       src/lib/DeepState.c
       src/lib/Log.c
       src/lib/Option.c
       src/lib/Stream.c
    )

    target_compile_options(${PROJECT_NAME}_LF PUBLIC -DLIBFUZZER -mno-avx -fsanitize=fuzzer-no-link,undefined)

    target_include_directories(${PROJECT_NAME}_LF
       PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
    )

    install(
       TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_LF
       LIBRARY DESTINATION lib
       ARCHIVE DESTINATION lib
    )
endif()

if (DEEPSTATE_HONGGFUZZ)
    add_library(${PROJECT_NAME}_HFUZZ STATIC
       src/lib/DeepState.c
       src/lib/Log.c
       src/lib/Option.c
       src/lib/Stream.c
    )

    target_compile_options(${PROJECT_NAME}_HFUZZ PUBLIC)

    target_include_directories(${PROJECT_NAME}_HFUZZ
       PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
    )

    install(
       TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_HFUZZ
       LIBRARY DESTINATION lib
       ARCHIVE DESTINATION lib
    )
endif()

if (DEEPSTATE_AFL)
    add_library(${PROJECT_NAME}_AFL STATIC
       src/lib/DeepState.c
       src/lib/Log.c
       src/lib/Option.c
       src/lib/Stream.c
    )

    target_compile_options(${PROJECT_NAME}_AFL PUBLIC -mno-avx)

    target_include_directories(${PROJECT_NAME}_AFL
       PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
    )

    install(
       TARGETS ${PROJECT_NAME} ${PROJECT_NAME}_AFL
       LIBRARY DESTINATION lib
       ARCHIVE DESTINATION lib
    )
endif()

if (DEEPSTATE_ANGORA)
	if(DEFINED ENV{USE_TRACK})
		set(PROJECT_NAME ${PROJECT_NAME}_taint)
	else()
		set(PROJECT_NAME ${PROJECT_NAME}_fast)
	endif()

	add_library(${PROJECT_NAME} STATIC
       src/lib/DeepState.c
       src/lib/Log.c
       src/lib/Option.c
       src/lib/Stream.c
    )

    target_compile_options(${PROJECT_NAME} PUBLIC -mno-avx)

    target_include_directories(${PROJECT_NAME}
       PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
    )

    install(
       TARGETS ${PROJECT_NAME}
       LIBRARY DESTINATION lib
       ARCHIVE DESTINATION lib
    )
endif()

set(SETUP_PY_IN "${CMAKE_SOURCE_DIR}/bin/setup.py.in")
set(SETUP_PY "${CMAKE_CURRENT_BINARY_DIR}/setup.py")
configure_file(${SETUP_PY_IN} ${SETUP_PY})

set(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/timestamp")
add_custom_command(
  OUTPUT ${OUTPUT}
  COMMAND ${PYTHON} ${SETUP_PY} build
  COMMAND ${CMAKE_COMMAND} -E touch ${OUTPUT}
)

# Install the Manticore harness.
add_custom_target(target ALL DEPENDS ${OUTPUT})

# Install DeepState via PIP.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
    #if an install prefix is not set, assume a global install
    install(CODE "execute_process(COMMAND ${PYTHON} ${SETUP_PY} install)")
else()
    # and install prefix is set; assume a user install
    # the "prefix=" is intentional
    install(CODE "execute_process(COMMAND ${PYTHON} ${SETUP_PY} install --user --prefix=)")
endif()

add_subdirectory(examples)

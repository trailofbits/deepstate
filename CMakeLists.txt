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

project(deepstate)
cmake_minimum_required(VERSION 2.8)

if (NOT DEFINED BUILD_LIBFUZZER AND DEFINED ENV{BUILD_LIBFUZZER}) 
  set(BUILD_LIBFUZZER "$ENV{BUILD_LIBFUZZER}") 
endif()

if (NOT DEFINED BUILD_AFL AND DEFINED ENV{BUILD_AFL})
  set(BUILD_AFL "$ENV{BUILD_AFL}")
endif()

if (NOT DEFINED BUILD_NOSTATIC AND DEFINED ENV{BUILD_NOSTATIC}) 
  set(BUILD_NOSTATIC "$ENV{BUILD_NOSTATIC}") 
endif()

if (BUILD_LIBFUZZER)
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

enable_language(C)
enable_language(CXX)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_DEBUG "-O3")
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(CMAKE_CXX_FLAGS_DEBUG "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

find_program(PYTHON "python3")

# Enable the GNU extensions
set(CMAKE_CXX_EXTENSIONS ON)

# Visual Studio already defaults to c++11
if (NOT WIN32)
  set(CMAKE_C_STANDARD 99)
  set(CMAKE_CXX_STANDARD 11)
endif()

add_library(${PROJECT_NAME} STATIC
  src/lib/DeepState.c
  src/lib/Log.c
  src/lib/Option.c
  src/lib/Stream.c
)

add_library(${PROJECT_NAME}32 STATIC
  src/lib/DeepState.c
  src/lib/Log.c
  src/lib/Option.c
  src/lib/Stream.c
)

target_compile_options(${PROJECT_NAME} PUBLIC -mno-avx)

target_compile_options(${PROJECT_NAME}32 PUBLIC -m32 -g3 -mno-avx)

if (NOT APPLE OR BUILD_NOSTATIC)
  target_link_libraries(${PROJECT_NAME} -static "-Wl,--allow-multiple-definition,--no-export-dynamic")
  target_link_libraries(${PROJECT_NAME}32 -static "-Wl,--allow-multiple-definition,--no-export-dynamic")
endif()

target_include_directories(${PROJECT_NAME}
  PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
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

if (BUILD_LIBFUZZER)
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

if (BUILD_AFL)
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

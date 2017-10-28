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

project(mctest)
cmake_minimum_required(VERSION 2.8)

enable_language(C)
enable_language(CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_FLAGS_DEBUG "-O3")
set(CMAKE_C_FLAGS_RELEASE "-O3")

set(CMAKE_CXX_FLAGS_DEBUG "-O3")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

find_program(PYTHON "python")

# Enable the GNU extensions
set(CMAKE_CXX_EXTENSIONS ON)

# Visual Studio already defaults to c++11
if (NOT WIN32)
  set(CMAKE_CXX_STANDARD 11)
endif ()

add_library(${PROJECT_NAME} STATIC
  src/lib/McTest.c
)

target_include_directories(${PROJECT_NAME}
  PUBLIC SYSTEM "${CMAKE_SOURCE_DIR}/src/include"
)

# Install the 
install(
  DIRECTORY "${CMAKE_SOURCE_DIR}/src/include/mctest"
  DESTINATION include
)

# Install the library
install(
  TARGETS ${PROJECT_NAME}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
)

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

# Install McTest via PIP.
install(CODE "execute_process(COMMAND ${PYTHON} ${SETUP_PY} install)")

add_subdirectory(examples)

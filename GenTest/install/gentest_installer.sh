#!/bin/bash

# Install Manifests
DeepState_C_Manifest='48i/* Standalone Output Flags for GenTest software */\nDEFINE_string(input_translation_config, InputOutputGroup, "", "Name of the file containing the translation " \n              "configuration for creating standalone tests."\n             );\nDEFINE_string(output_standalone_test, InputOutputGroup, "", "Name of the file to write standalone test to.");\nDEFINE_string(output_num, InputOutputGroup, "", "The number of standalone output tests to generate. Only works with --fuzz flag." );\nDEFINE_string(input_source_file, InputOutputGroup, "", "Name of source file to create standalone version of.");'
DeepState_H_Manifest='93iDECLARE_string(output_standalone_test);\nDECLARE_string(input_source_file);\nDECLARE_string(output_num);\nDECLARE_string(input_translation_config);'
DeepState_H_Manifest_2='/static int DeepState_Run(void) {/ a  if (HAS_FLAG_output_standalone_test) {\n      return DeepStateCreateStandalone( FLAGS_output_standalone_test,\n                                        FLAGS_input_source_file,\n                                        FLAGS_input_test_file,\n                                        FLAGS_input_translation_config,\n					FLAGS_input_test_dir,\n					FLAGS_output_num,\n					FLAGS_fuzz,\n					FLAGS_fuzz && FLAGS_exit_on_fail,\n FLAGS_input_which_test                                     );\n  }'
DeepState_H_Manifest_3='/Stream.h>/ a #include <deepstate/GenTestBridge.h>'
DeepState_CMake_Manifest_1='143ifile( GLOB gentest_header_files "${CMAKE_SOURCE_DIR}/GenTest/include/modules/*" )\nfile( GLOB gentest_files "${CMAKE_SOURCE_DIR}/GenTest/src/modules/*/*.cpp" )\nfile( GLOB gentest_lib "${CMAKE_SOURCE_DIR}/GenTest/lib/*.a" )'
DeepState_CMake_Manifest_2='/add_library(${PROJECT_NAME} STATIC/ a src/lib/GenTestBridge.cpp\n  ${gentest_files}\n  ${gentest_lib}'
DeepState_CMake_Manifest_3='/target_compile_options(${PROJECT_NAME} PUBLIC -mno-avx)/ a target_link_libraries( deepstate ${gentest_lib} )\n'
DeepState_CMake_Manifest_4='/target_include_directories(${PROJECT_NAME}/ a PUBLIC SYSTEM "${gentest_header_files}"\n'
DeepState_CMake_Ex_Manifest='29i    target_link_libraries(${file_no_ext} ${gentest_lib} "-Wl,--whole-archive -lpthread -Wl,--no-whole-archive" )\n'

current_dir=$PWD
DeepState_CPP=${current_dir}/../../src/lib
DeepState_HPP=${current_dir}/../../src/include/deepstate
DeepState_Examples=${current_dir}/../../examples
DeepState_Top=${current_dir}/../../

# Starting install message
echo "GenTest installation commenced..."
echo "Configuring files with GenTest links..."
echo
echo

# Configure GenTest bridge in appropriate directory locations.
mv ../DeepState_Files/GenTestBridge.cpp ${DeepState_CPP}
mv ../DeepState_Files/GenTestBridge.h ${DeepState_HPP}

# Configure DeepState.c and DeepState.h
sed -i "${DeepState_C_Manifest}" ${DeepState_CPP}/DeepState.c
sed -i "${DeepState_H_Manifest}" ${DeepState_HPP}/DeepState.h
sed -i "${DeepState_H_Manifest_2}" ${DeepState_HPP}/DeepState.h
sed -i "${DeepState_H_Manifest_3}" ${DeepState_HPP}/DeepState.h

# Configure DeepState CMake
sed -i "${DeepState_CMake_Manifest_1}" ${DeepState_Top}/CMakeLists.txt
sed -i "${DeepState_CMake_Manifest_2}" ${DeepState_Top}/CMakeLists.txt
sed -i "${DeepState_CMake_Manifest_3}" ${DeepState_Top}/CMakeLists.txt
sed -i "${DeepState_CMake_Manifest_4}" ${DeepState_Top}/CMakeLists.txt

# Configure DeepState Ex CMake
sed -i "${DeepState_CMake_Ex_Manifest}" ${DeepState_Examples}/CMakeLists.txt

echo
echo "Configuration complete."
echo "Making DeepState...."
echo "Navigate to: "${current_dir}/../../
cd ${current_dir}/../../
mkdir -p build && cd build
cmake ../
make
sudo make install
gedit ../GenTest/README.md



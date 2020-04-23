project(GenTest)
cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 11)

include_directories(include/modules/BinaryParser)
include_directories(include/modules/FileAssembler)
include_directories(include/modules/TranslationEngine)
include_directories(include/modules/util)
include_directories(include/modules/antlr4-runtime)

add_executable(GenTest src/main.cpp)

add_compile_options( "-Wall" "-std=c++11" "-Wextra"
                     "$<$<CONFIG:DEBUG>:-O0;-g>" 
					 "$<$<CONFIG:RELEASE>:-O3>")

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_BUILD_TYPE RelWithDebInfo)

add_library(gentest_binaryparser STATIC src/modules/BinaryParser/BinaryParser.cpp
        src/modules/BinaryParser/BinaryIterator.cpp
	src/modules/BinaryParser/BinaryController.cpp
  )
add_library(gentest_fileassembler STATIC src/modules/FileAssembler/FileAssembler.cpp
	    src/modules/FileAssembler/SymbolicGenerator.cpp
	    src/modules/FileAssembler/LoopHandler.cpp
)
add_library(gentest_translationengine STATIC src/modules/TranslationEngine/TranslationEngine.cpp
	    src/modules/TranslationEngine/GenTestParser.cpp
	    src/modules/TranslationEngine/GenTestListener.cpp
	    src/modules/TranslationEngine/GenTestLexer.cpp
	    src/modules/TranslationEngine/GenTestBaseListener.cpp
	    src/modules/TranslationEngine/CrudeListener.cpp
	    src/modules/TranslationEngine/ASTListener.cpp)
add_library(gentest_util STATIC src/modules/util/Util.cpp
        src/modules/util/DataStructures.cpp
           )

set( GENTEST_MODULES 
     gentest_binaryparser
	 gentest_fileassembler
	 gentest_translationengine
	 gentest_util 
   )


target_link_libraries( gentest_translationengine gentest_binaryparser )
target_link_libraries( gentest_translationengine ${CMAKE_CURRENT_SOURCE_DIR}/lib/libantlr4-runtime.a )
target_link_libraries( gentest_binaryparser ${CMAKE_CURRENT_SOURCE_DIR}/../build/libdeepstate.a )
target_link_libraries( gentest_fileassembler ${CMAKE_CURRENT_SOURCE_DIR}/../build/libdeepstate.a )

option( BUILD_TESTS OFF "Determines whether to build tests." )
if(BUILD_TESTS)

  include_directories(lib)
  add_executable(gentest_test test/TestMain.cpp)
  add_library( test_lib STATIC
          test/modules/TestBinaryParser.cpp
          test/modules/TestFileAssembler.cpp
          test/modules/TestTranslationEngine.cpp
          test/modules/TestUtil.cpp
  )  
  enable_testing()

  target_link_libraries(gentest_test PUBLIC
                        test_lib
						${GENTEST_MODULES}
                       )

  add_test( NAME test COMMAND gentest_test ) 
endif()

target_link_libraries(GenTest 
					  ${GENTEST_MODULES}
					 )

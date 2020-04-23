#define CATCH_CONFIG_MAIN // DO NOT define this anywhere else
#include "catch.hpp"
#include "BinaryParser.h"
#include "TranslationEngine.h"
#include "FileAssembler.h"
#include "Util.h"
#include "DataStructures.h"


// BinaryParser Tests
TEST_CASE( "Test Parser and Iterator", "[binary_parser]" )

{
    BinaryParser bp;

    REQUIRE_THROWS( bp.getIterator() );
    REQUIRE_THROWS( bp.parse( "invalid_file_name" ) );

    bp.parse( "../test/test_data/binary_test_20b.test" );

    auto iter = bp.getIterator();

    SECTION( "Binary Iterator UChar" )
        {
            for( int index = 0; index < 20; ++index )
                {
                    // i know the layout of the file
                    unsigned char a = iter.nextUChar();
                    REQUIRE( a == (unsigned char) index  );

                }

            // end of the road, error should be thrown
            REQUIRE_THROWS( iter.nextUChar() );
        }

    SECTION( "Rewinding more positions than the size of the buffer "
             "resets index to zero."
             )
        {

            iter.rewind( 2000000 );
            REQUIRE( iter.nextUChar() == 0x00 );

            iter.rewind();
            iter.nextInt();
            REQUIRE( iter.nextUChar() == 0x04 );
        }

    iter.rewind();

    SECTION( "Binary Iterator Int" )
        {
            int a = iter.nextInt();

            // reverse order of bytes because x86 is little-endian
            REQUIRE( a == 0x03020100 );
        }

    iter.rewind( 200 );


}

TEST_CASE( "Test Parser and Iterator with deepstate values", "[binary_parser]" ) {
    BinaryParser bp;

    bp.parse("../test/test_data/test.new");

    auto iter = bp.getIterator();

    SECTION("Binary Iterator Get Value")
    {
        while (true) {
            auto test = iter.nextInt();

            std::cout << test << std::endl;

            REQUIRE(test != -1406192183);
        }

        // end of the road, error should be thrown
    }
}

// FileAssembler Tests


// TE Constants
const int TEST_EULER = 0;
const int TEST_OVERFLOW = 1;
const int TEST_CRASH = 2;
const int TEST_ENCRASH = 3;
const int TEST_PRIMES = 4;
const int TEST_EULER_MOD = 5;

// TE Support Functions
std::vector<std::vector<Node>> fetchTestFiles()
{
    // Create vector structrue.
    static std::vector<std::vector<Node>> test_asts;
    static int counter = 0;

    if( counter == 0 )
    {

        // Test File Paths
        // Note: If running on new system, please change path of 
        // test directory to its position on your system.
        std::string TEST_DIR = "/home/iroh/Documents/CS486/Team22/test/test_data/";
        std::string eulerTest = TEST_DIR + "Euler.cpp";
        std::string intOverflowTest = TEST_DIR + "IntegerOverflow.cpp";
        std::string crashTest = TEST_DIR + "Crash.cpp";
        std::string ensembledCrashTest = TEST_DIR + "EnsembledCrash.cpp";
        std::string primesTest = TEST_DIR + "Primes.cpp";
        std::string eulerModTest = TEST_DIR + "EulerModified.cpp";

        // Declare Translation Engine object.
        TranslationEngine parser;

        // Fetch parsing results from parser.
        std::vector<Node> resultEuler = parser.getAST( eulerTest );
        std::vector<Node> resultIntOverflow = parser.getAST( intOverflowTest );
        std::vector<Node> resultCrash = parser.getAST( crashTest );
        std::vector<Node> resultEnCrash = parser.getAST( ensembledCrashTest );
        std::vector<Node> resultPrimes = parser.getAST( primesTest );
        std::vector<Node> resultEulerMod = parser.getAST( eulerModTest );

        // Add results
        test_asts.push_back( resultEuler );
        test_asts.push_back( resultIntOverflow );
        test_asts.push_back( resultCrash );
        test_asts.push_back( resultEnCrash );
        test_asts.push_back( resultPrimes );
        test_asts.push_back( resultEulerMod );

        // Increment counter
        counter++;
    }

    return test_asts;
}


int getTargetCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type != NO_TRANSLATE )
        {
            targetCount++;
        }
    }

    return targetCount;
}


int getIncludeCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type == INCLUDE )
        {
            targetCount++;
        }
    }

    return targetCount;
}


int getTestCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type == TEST )
        {
            targetCount++;
        }
    }

    return targetCount;
}


int getAssertCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type >= ASSERT_GT &&  
            resultVector.at( i ).type <= ASSERT )
        {
            targetCount++;
        }
    }

    return targetCount;
}


int getAssumeCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type >= ASSUME_GT &&  
            resultVector.at( i ).type <= ASSUME )
        {
            targetCount++;
        }
    }

    return targetCount;
}

int getCheckCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type >= CHECK_GT &&  
            resultVector.at( i ).type <= CHECK )
        {
            targetCount++;
        }
    }

    return targetCount;
}


int getDeepStateCount( std::vector<Node> resultVector )
{
    int targetCount = 0;

    for( int i = 0; i < (int) resultVector.size(); i++ )
    {
        if( resultVector.at( i ).type >= DEEPSTATE_ASSERT &&  
            resultVector.at( i ).type <= DEEPSTATE_MALLOC )
        {
            targetCount++;
        }
    }

    return targetCount;
}


// TranslationEngine Tests
TEST_CASE( "Correct Targets Test", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   For loops
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getTargetCount( tests[ TEST_EULER ] ) == 19 ); 
    REQUIRE( getTargetCount( tests[ TEST_OVERFLOW ] ) == 10 );
    REQUIRE( getTargetCount( tests[ TEST_CRASH ] ) == 5 );
    REQUIRE( getTargetCount( tests[ TEST_ENCRASH ] ) == 9 );
    REQUIRE( getTargetCount( tests[ TEST_PRIMES ] ) == 20 );
}


TEST_CASE( "All Includes Found", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getIncludeCount( tests[ TEST_EULER ] ) == 1 ); 
    REQUIRE( getIncludeCount( tests[ TEST_OVERFLOW ] ) == 2 );
    REQUIRE( getIncludeCount( tests[ TEST_CRASH ] ) == 1 );
    REQUIRE( getIncludeCount( tests[ TEST_ENCRASH ] ) == 1 );
    REQUIRE( getIncludeCount( tests[ TEST_PRIMES ] ) == 1 );
}

TEST_CASE( "All Tests Found", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getTestCount( tests[ TEST_EULER ] ) == 1 ); 
    REQUIRE( getTestCount( tests[ TEST_OVERFLOW ] ) == 2 );
    REQUIRE( getTestCount( tests[ TEST_CRASH ] ) == 1 );
    REQUIRE( getTestCount( tests[ TEST_ENCRASH ] ) == 1 );
    REQUIRE( getTestCount( tests[ TEST_PRIMES ] ) == 2 );
}

TEST_CASE( "All ASSERTS Found", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getAssertCount( tests[ TEST_EULER ] ) == 16 ); 
    REQUIRE( getAssertCount( tests[ TEST_OVERFLOW ] ) == 2 );
    REQUIRE( getAssertCount( tests[ TEST_CRASH ] ) == 1 );
    REQUIRE( getAssertCount( tests[ TEST_ENCRASH ] ) == 2 );
    REQUIRE( getAssertCount( tests[ TEST_PRIMES ] ) == 2 );
}

TEST_CASE( "All ASSUMES Found", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getAssumeCount( tests[ TEST_EULER ] ) == 0 ); 
    REQUIRE( getAssumeCount( tests[ TEST_OVERFLOW ] ) == 0 );
    REQUIRE( getAssumeCount( tests[ TEST_CRASH ] ) == 0 );
    REQUIRE( getAssumeCount( tests[ TEST_ENCRASH ] ) == 0 );
    REQUIRE( getAssumeCount( tests[ TEST_PRIMES ] ) == 5 );
}

TEST_CASE( "All Checks Found", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getCheckCount( tests[ TEST_EULER ] ) == 0 ); 
    REQUIRE( getCheckCount( tests[ TEST_OVERFLOW ] ) == 0 );
    REQUIRE( getCheckCount( tests[ TEST_CRASH ] ) == 0 );
    REQUIRE( getCheckCount( tests[ TEST_ENCRASH ] ) == 0 );
    REQUIRE( getCheckCount( tests[ TEST_PRIMES ] ) == 0 );
}

TEST_CASE( "All DeepState_clause Found", "[translation_engine]" )
{
    std::vector<std::vector<Node>> tests = fetchTestFiles();

    // Any of the following are considered targets:
    //   ASSERT/ASSUME/CHECK clauses.
    //   TEST function declarations.
    //   Include statements.
    //   Symbolic statements.
    //   Calls to DeepState_type or DeepState_Malloc
    //   DEEPSTATE_INLINE, DEEPSTATE_NOINLINE, DEEPSTATE_NORETURN
    REQUIRE( getDeepStateCount( tests[ TEST_EULER ] ) == 0 ); 
    REQUIRE( getDeepStateCount( tests[ TEST_OVERFLOW ] ) == 0 );
    REQUIRE( getDeepStateCount( tests[ TEST_CRASH ] ) == 0 );
    REQUIRE( getDeepStateCount( tests[ TEST_ENCRASH ] ) == 2 );
    REQUIRE( getDeepStateCount( tests[ TEST_PRIMES ] ) == 7 );
}

// Util Tests

// Data Structures Tests

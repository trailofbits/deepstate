#include "deepstate/GenTestBridge.h"
#include <iostream>
#include <string>
#include "TranslationEngine.h"
#include "FileAssembler.h"
#include "dirent.h"

int DeepStateCreateStandalone( const char *output_filename,
                               const char *input_source_filename,
                               const char *binary_filename,
                               const char *translation_config_filename,
                               const char *input_dir,
                               const char *run_num,
                               const bool standard_fuzz,
                               const bool fuzz_until_fail
                             )
{
    // Convert const char to string.
    std::string inputDir( input_dir );
    std::string inputName( input_source_filename );
    std::string outBaseName ( output_filename );
    std::string binaryName( binary_filename );
    std::string fuzzFlag( std::to_string( standard_fuzz ) );
    std::string untilFail( std::to_string( fuzz_until_fail ) );
    std::string runNum( run_num );
    int runTimes = 1;
    
    // Basic data structures.
    std::vector<std::string> fileList;
    TranslationEngine parser;
    std::string outName = outBaseName;

    // Setup run_num
    if( runNum.size() != 0 )
    {
        runTimes = stoi( runNum );
    }

    // Initialize all files in provided directory if provided.
    if( inputDir.size() > 0 )
    {
        // Setup variables.
	    DIR * dir;
	    struct dirent * ent;

        // If the directory exists get files.
	    if( ( dir = opendir( input_dir ) ) != NULL ) 
	    {
            while( ( ent = readdir( dir ) ) != NULL )
            {
                // Get filename
                std::string fileName( ent->d_name );

                // If the filename is no '../' or './' on linux
                if( fileName.compare(".") != 0 && fileName.compare( ".." ) != 0 )
                {
                   fileList.push_back( inputDir + ent->d_name );
                }
            }

            // Close directory
            closedir( dir );
	    }
    }
    else // Otherwise only provide one file, the input file name.
    {
        fileList.push_back( binaryName );
    }

    // Parse and build translation
    std::vector<Node> output = parser.getAST( inputName );

    for( int i = 0; i < runTimes; i++ )
    {
        outName = outBaseName;
        outName.insert( outName.find( ".cpp" ), + "_" + std::to_string( i ) );

        buildFile( output, fileList, outName.c_str(), translation_config_filename,
                   standard_fuzz, fuzz_until_fail );

    }

    return 1;
}


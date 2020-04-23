// Program Information //////////////////////////////////////////////
/**
  * @file main.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief This will be the main runner class for GenTest
  *
  * @details This class will be used for creating and starting GenTest
  *          and its other functions
  *
  * @version 0.01
  *          Tristan Miller ( 5 November 2019 )
  *          Created skeleton for class layout

  (Legal terms of use/libraries used need to be added here once we get to that point)

**/

#include <iostream>
#include "TranslationEngine.h"
#include "FileAssembler.h"
#include <dirent.h>

//number of args (test, binary, output name)
int NUM_ARGS = 7;

using namespace std;

int main( int numArgs, char** args )
{
    //numArgs - 1 because args[0] is the name of the program
    if( numArgs - 1 != NUM_ARGS )
    {
        //probably want to create/utilize some sort of logger

        cout << "Invalid number of args" << endl;

        return 0;
    }

    // Setting up some local variables to make code more readable
    char * binaryFile = args[ 2 ], 
	 * outputPath = args[ 3 ],
	 * translateCFG = args[ 4 ],
     	 * input_dir = args[ 5 ],
	 * fuzz_flag = args[ 6 ],
         * until_fail_flag = args[ 7 ];
  
    // Initialize directory variables.
    std::string inputDir;
    std::string name( binaryFile );
    std::vector<std::string> fileList;

    if( input_dir == NULL )
    {
        inputDir = "";
    }
    else
    {
        inputDir = input_dir;
    }

    // Initialize all files in provided directory if provided.
    if( inputDir.compare( "none" ) )
    {
	    DIR * dir;
	    struct dirent * ent;

	    if( ( dir = opendir( input_dir ) ) != NULL ) 
	    {
            while( ( ent = readdir( dir ) ) != NULL )
            {
                std::string fileName( ent->d_name );

                if( fileName.compare(".") != 0 && fileName.compare( ".." ) != 0 )
                {
            
                   fileList.push_back( inputDir + ent->d_name );
                }
            }

            closedir( dir );
	    }

	
    }
    else // Otherwise only provide one file, the input file name.
    {
        fileList.push_back( name );
    }

    // Create parser object.
    TranslationEngine parser;

    // Store fileToTranslate
    std::string fileToTranslate = args[ 1 ];

    // Get output.
    std::vector<Node> output = parser.getAST( fileToTranslate );

    
    //buildFile(output, fileList, outputPath, translateCFG);

}

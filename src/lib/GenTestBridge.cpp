#include "deepstate/GenTestBridge.h"
#include <iostream>
#include <string>
#include "TranslationEngine.h"
#include "FileAssembler.h"

int DeepStateCreateStandalone( const char *output_filename,
                               const char *input_source_filename,
                               const char *binary_filename,
                               const char *translation_config_filename
                             )
{
    std::string outputName( output_filename );
    std::string inputName( input_source_filename );
    std::string binaryName( binary_filename );
    std::string configName( translation_config_filename );
    std::string statement = "../../Team22/./GenTest " + inputName + " " + binaryName + " " + outputName + 
			    " " + configName;

    system( statement.c_str() );

    return 1;
}

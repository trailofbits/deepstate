#include "deepstate/GenTestBridge.h"
#include "BinaryParser.h"
#include "BinaryIterator.h"
#include <iostream>
#include <string>

int DeepStateCreateStandalone( const char *output_filename,
                               const char *input_source_filename,
                               const char *binary_filename,
                               const char *translation_config_filename
                             )
{
    BinaryParser b;
    b.parse( std::string( binary_filename ) );
    auto iter = b.getIterator();
    int n = iter.nextInt();

    std::cout << n  << std::endl;
    std::cout << n  + n << std::endl;
    std::cout << std::string( input_source_filename ) << std::endl;
}

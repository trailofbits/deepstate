// Program Information //////////////////////////////////////////////
/**
  * @file BinaryParser.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Creation of binary values using DeepState
  *
  * @details This class will be deconstruct binary files (foo.test) and create values
  *          for insertion into the vector class. This could potentially be added into
  *          the TranslationEngine ( or the TranslationEngine calls this )
  *
  * @version 0.01
  *          Tristan Miller ( 5 November 2019 )
  *          Created skeleton for class layout
  (Legal terms of use/libraries used need to be added here once we get to that point)
**/
#include "BinaryParser.h"
#include <deepstate/DeepState.h>

#include <cstdint>
#include <cstring>
#include <stdexcept>

void BinaryParser::parse( const std::string& filename )
{
    DeepState_InitInputFromFile( filename.c_str() );
    

}

BinaryIterator BinaryParser::getIterator()
{
    return BinaryIterator( &data );
}

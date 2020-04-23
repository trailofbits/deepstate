// Program Information //////////////////////////////////////////////
/**
  * @file BinaryIterator.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Creation of binary values using DeepState
  *
  * @details This class will be deconstruct binary files (foo.test) and create values
  *          for insertion into the vector class. This could potentially be added into
  *          the TranslationEngine ( or the TranslationEngine calls this )
  *
  * @version 1.00
  *          Zane Fink
  *          Created skeleton for class layout
  (Legal terms of use/libraries used need to be added here once we get to that point)
**/

#include "BinaryIterator.h"
#include <deepstate/DeepState.h>

int BinaryIterator::nextInt()
{
    return DeepState_Int();
}

unsigned int BinaryIterator::nextUInt()
{
    return DeepState_UInt();;
}

unsigned char BinaryIterator::nextUChar()
{
    return DeepState_UChar();
}

char BinaryIterator::nextChar()
{
    return DeepState_Char();
}

std::size_t BinaryIterator::nextSize_t()
{
    return DeepState_Size();
}

short BinaryIterator::nextShort()
{
    return DeepState_Short();
}

void BinaryIterator::rewind()
{
    rewind( 1 );
}

void BinaryIterator::rewind( std::size_t step )
{
    if( step > index )
        {
            index = 0;
        }
    else
        {
            index -= step;
        }
}

std::uint64_t BinaryIterator::nextUInt64()
{

    return DeepState_UInt64();
}

std::int64_t BinaryIterator::nextInt64()
{
    return DeepState_Int64();
}

std::uint16_t BinaryIterator::nextUInt16()
{

    return static_cast<std::uint16_t>( DeepState_Short() );
}

std::int16_t BinaryIterator::nextInt16()
{
    return DeepState_Short();
}

long BinaryIterator::nextLong()
{
    return DeepState_Long();
}

float BinaryIterator::nextFloat()
{
    return DeepState_Float();
}

double BinaryIterator::nextDouble()
{
    return DeepState_Double();
}

int BinaryIterator::nextRandInt()
{
    return DeepState_RandInt();
}

bool BinaryIterator::nextBool()
{
    return DeepState_Bool();
}

std::string BinaryIterator::nextString( std::size_t len, const char *allowed )
{
    return std::string{ DeepState_CStr_C( len, allowed ) };
}

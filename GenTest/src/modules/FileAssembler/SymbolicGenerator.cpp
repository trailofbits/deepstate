/**
  * @file SymbolicGenerator.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Management of Symbolic line generation through fuzzing or binary files. 
  *
  * @details This class is responsible for the management, retrieval, and construction 
  *          of symbolic values in a string line.
  *
  * @version 1.00
  *          Joshua Johnson - 4/22/2020
  *          Created skeleton for class layout
  *	     Joshua Johnson - 4/22/2020
  *	     Completed SymbolicGenerator alongside for-loop bug-fixes.
  *
  * COPYRIGHT INFORMATION
  *-----------------------------------------------------------------
  * Copyright (c) 2020 Trail of Bits, Inc.
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *     http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations unde
**/



/*******************
* Headers 
********************/
#include "SymbolicGenerator.h"



/*******************
* Constructors
********************/



SymbolicGenerator::SymbolicGenerator( BinaryController * ctr, BinaryIterator * it, 
                                      ResultPacket &results, bool fuzz )
{
    this->ctr = ctr;
    this->it = it;
    this->fuzz = fuzz;
    this->results = results;
}


SymbolicGenerator::SymbolicGenerator( BinaryController *& ctr, ResultPacket &results )
{
    this->ctr = ctr;
    this->it = it;
    this->fuzz = true;
    this->results = results;
}



/*******************
* Binary File Alg.
********************/


void SymbolicGenerator::setIterator( std::vector<std::string> binaryFiles )
{
    static int bFileCounter = 0;
    BinaryParser bp;

    if( bFileCounter < binaryFiles.size() )
    {
        // Get binary file and parse.
        bp.parse( binaryFiles.at( bFileCounter ) );

        // Get interator
        static auto it = bp.getIterator();

        // Increment counter
        bFileCounter++;

        this->it = &it;
    }
    else
    {
        this->it = NULL;
    }
}


BinaryIterator * SymbolicGenerator::getIterator()
{
    return this->it;
}


int SymbolicGenerator::getInt( BinaryIterator * it )
{
    return it->nextInt();
}


unsigned int SymbolicGenerator::getUInt( BinaryIterator * it )
{
    return it->nextUInt();
}


int16_t SymbolicGenerator::getInt16( BinaryIterator * it )
{
    return it->nextInt16();
}


int64_t SymbolicGenerator::getInt64( BinaryIterator * it )
{
    return it->nextInt64();
}


uint16_t SymbolicGenerator::getUInt16( BinaryIterator * it )
{
    return it->nextUInt16();
}


uint64_t SymbolicGenerator::getUInt64( BinaryIterator * it )
{
    return it->nextUInt64();
}


short SymbolicGenerator::getShort( BinaryIterator * it )
{
    return it->nextShort();
}


long SymbolicGenerator::getLong( BinaryIterator * it )
{
    return it->nextLong();
}


double SymbolicGenerator::getDouble( BinaryIterator * it )
{
    return it->nextDouble();
}


float SymbolicGenerator::getFloat( BinaryIterator * it )
{
    return it->nextFloat();
}


char SymbolicGenerator::getChar( BinaryIterator * it )
{
    return it->nextChar();
}


unsigned char SymbolicGenerator::getUChar( BinaryIterator * it )
{
    return it->nextUChar();
}


std::string SymbolicGenerator::getSymbolic( std::string datatype )
{
    // Declare local variables.
    std::ostringstream out;

    if( !this->fuzz )
    {
        if( this->it == NULL )
        {
            return "0";
        }
        if( datatype == "int" || datatype == "int32_t" )
        {
            return std::to_string( this->getInt( this->it ) );
        }
        else if( datatype == "int16_t" )
        {
            return std::to_string( this->getInt16( this->it ) );
        }
        else if( datatype == "int64_t" )
        {
            return std::to_string( this->getInt64( this->it ) );
        }   
        else if( datatype == "unsigned int" || datatype == "unsigned"
                 || datatype == "uint32_t" )
        {
            return std::to_string( this->getUInt( this->it ) );
        }
        else if( datatype == "uint16_t" )
        {
            return std::to_string( this->getUInt16( this->it ) );
        }
        else if( datatype == "uint64_t" )
        {
            return std::to_string( this->getUInt64( this->it ) );
        }
        else if( datatype == "short" )
        {
            return std::to_string( this->getShort( this->it ) );
        }
        else if( datatype == "long" )
        {
            return std::to_string( this->getLong( this->it ) );
        }
        else if( datatype == "double" )
        {
            return std::to_string( this->getDouble( this->it ) );
        }
        else if( datatype == "float" )
        {
            return std::to_string( this->getFloat( this->it ) );
        }
        else if( datatype == "char" || datatype == "int8_t" )
        {
            return std::to_string( this->getChar( this->it ) );
        }
        else if( datatype == "unsigned char" || datatype == "uint8_t" )
        {
            return std::to_string( this->getUChar( this->it ) );
        }
    
    }
    else
    {
        if( datatype == "int" || datatype == "int32_t" )
        {
            results.set_read_bytes( results.get_bytes() - 4 );            

            return  std::to_string( this->ctr->getInt() );
        }
        else if( datatype == "int16_t" )
        {
            results.set_read_bytes( results.get_bytes() - 2 );    

            return std::to_string( this->ctr->getShort() );
        }
        else if( datatype == "int64_t" )
        {
            results.set_read_bytes( results.get_bytes() - 8 );  
  
            return std::to_string( this->ctr->getInt64() );
        }  
        else if( datatype == "unsigned int" || datatype == "unsigned" 
		 || datatype == "uint32_t" )
        {
            results.set_read_bytes( results.get_bytes() - 4 );  

            return std::to_string( this->ctr->getUInt() );
        } 
        else if( datatype == "uint16_t" )
        {
            results.set_read_bytes( results.get_bytes() - 2 );  

            return std::to_string( this->ctr->getUShort() );
        }
        else if( datatype == "uint64_t" )
        {
            results.set_read_bytes( results.get_bytes() - 8 );  

            return std::to_string( this->ctr->getUInt64() );
        }
        else if( datatype == "short" )
        {
            results.set_read_bytes( results.get_bytes() - 2 );              

            return std::to_string( this->ctr->getShort() );
        }
        else if( datatype == "long" )
        {
            results.set_read_bytes( results.get_bytes() - 8 );  

            return std::to_string( this->ctr->getLong() );
        }
        else if( datatype == "double" )
        {
            results.set_read_bytes( results.get_bytes() - 8 );  

            out << std::scientific << this->ctr->getDouble();

            return out.str();
        }
        else if( datatype == "float" )
        {
            results.set_read_bytes( results.get_bytes() - 4 );  

            out << std::scientific << this->ctr->getFloat();

            return out.str();
        }
        else if( datatype == "char" || datatype == "int8_t" )
        {
            results.set_read_bytes( results.get_bytes() - 1 ); 
 
            return std::to_string( this->ctr->getChar() );
        }
        else if( datatype == "unsigned char" || datatype == "uint8_t" )
        {
            results.set_read_bytes( results.get_bytes() - 1 );  

            return std::to_string( this->ctr->getUChar() );
        }
	    else if( datatype == "bool" )
	    {
	        results.set_read_bytes( results.get_bytes() - 1 );  

            return std::to_string( this->ctr->getBool() );
	    }
    }
}


std::string SymbolicGenerator::writeSymbolicLine( std::string varName, std::string datatype )
{
    return datatype + " " + varName + " = " + getSymbolic( datatype ) + ";";
}


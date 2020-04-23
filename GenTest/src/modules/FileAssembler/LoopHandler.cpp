/**
  * @file LoopHandler.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Management of loops with symbolic declarations.
  *
  * @details This class is responsible for the management, retrieval, and construction 
  *          of symbolic values for loop structures.
  *
  * @version 1.00
  *          Joshua Johnson - 4/22/2020
  *          Created skeleton for class layout
  *	     Joshua Johnson - 4/22/2020
  *	     Completed LoopHandler alongside for-loop bug-fixes.
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


#include "LoopHandler.h"

/********************************
* Loop Handler Code
*********************************/



LoopHandler::LoopHandler()
{
    this->outputPos = -9999999;
    this->multiType = this->createSymbolic = false;
}

LoopHandler::LoopHandler( BinaryController * ctr )
{
    this->outputPos = -9999999;
    this->multiType = false;
    this->ctr = ctr;
    this->createSymbolic = true;
}

void LoopHandler::addType( std::string type )
{
    if( !this->isInManifest( type ) )
    {
        this->typeManifest.push_back( type );
    }
}

void LoopHandler::setPos( int pos )
{
    this->outputPos = pos;
}

bool LoopHandler::isInManifest( std::string type )
{
    // Declare variables.
    bool passFail = false;

    for( int i = 0; i < (int) this->typeManifest.size(); i++ )
    {
        passFail = ( typeManifest.at( i ) == type ) || passFail;
    }

    return passFail;
}

std::string LoopHandler::writeSymbolicParams( ResultPacket &results )
{
    //Declare local variables.
    int num_bytes = 0;
    SymbolicGenerator generator( this->ctr, results );
    std::string output = "", type;

    for( int pos = 0; pos < (int) typeManifest.size(); pos++ )
    {
        type = this->typeManifest.at( pos );
        output += "\n" + type + " SYMBOLIC_LOOP_PARAMS [] = { ";        
    
        // Initialize num_bytes
        num_bytes = ( (type == "int" || type == "long" || type == "float" ||
                     type == "unsigned" || type == "unsigned int" || 
                     type == "uint32_t"  ) * FOUR_BYTES
                    + ( type == "short" || type == "uint16_t"  ) * TWO_BYTES
                    + ( type == "char" || type == "unsigned char" || type == "bool" || 
                        type == "uint8_t" ) * ONE_BYTE 
                    + ( type == "double" || type == "uint64_t" ) * EIGHT_BYTES );

        // Iterate until the end of bytes.
        for( int i = 0; i < ( results.get_bytes() / num_bytes ) - num_bytes; i++ )
        {
            if( i % 5 == 0 && i > 0 )
            {
                output += "\n";
            }

            if( i < ( ( results.get_bytes() / num_bytes ) - num_bytes ) - 1 )
            {
               output += generator.getSymbolic( this->typeManifest.at( pos ) ) + ", ";
            }
            else
            {
               output += generator.getSymbolic( this->typeManifest.at( pos ) );
            }
        }

        output += " };\n";
    }
   

    return output;
}

std::string LoopHandler::writeSymbolicStatement( std::string datatype, std::string currentText, std::string loopText )
{
    StructHandler handler;
    std::string variableName, loopVar = loopText;

    // Get VariableName
    variableName = handler.getVarName( currentText );

    // Get loop var name;
    loopVar = loopVar.substr( 0, loopVar.find( "=" ) );
    loopVar = loopVar.substr( loopVar.find( "(" ) + 1, loopVar.length() - 1 ); 
    loopVar = loopVar.substr( loopVar.find_first_not_of( " " ), loopVar.length() ); 
    loopVar = loopVar.substr( loopVar.find( " " ) + 1, loopVar.length() );
    loopVar = loopVar.substr( 0, loopVar.find_last_of( " " ) ); 

    return datatype + " " + variableName + " = SYMBOLIC_LOOP_PARAMS[ " + loopVar + " ];\n\n"; 
}


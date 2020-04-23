// Program Information //////////////////////////////////////////////
/**
  * @file DataStructures.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Storage of different data structure classes
  *
  * @details This class will be used for the creation and storage for code
  *           relating to created data structures
  *
  * @version 0.01
  *          Tristan Miller ( 5 November 2019 )
  *          Created skeleton for class layout

  (Legal terms of use/libraries used need to be added here once we get to that point)

**/

// data structures go here as needed ( we can split these into separate files for readability if need be )

#include "DataStructures.h"


//Translation Dictionary Methods
bool TranslationDictionary::loadFile( const std::string& filePath )
{
    configFile.open( filePath );

    //loops over each line of cfg file
    while( !configFile.eof() )
    {
        std::string currentTrans, nTerminal, translateTo;

        std::getline( configFile, currentTrans );

        auto location = currentTrans.find('=');

        //if invalid translation
        if( location == std::string::npos )
        {
            //log if this happens
        }
        else
        {
            nTerminal = currentTrans.substr(0, location );

            translateTo = currentTrans.substr( location + 1 );

            //replaces all "unnatural new lines" mainly for MAIN_FUNC
            while( translateTo.find('\\') != std::string::npos )
            {
                auto locationOfNewLine = translateTo.find_first_of('\\');

                translateTo = translateTo.substr(0,locationOfNewLine) + '\n'
                              + translateTo.substr(locationOfNewLine+2, translateTo.length());
            }

            TranslationEntry newEntry;

            newEntry.nTerminalVal = nTerminal;

            newEntry.translateTo = translateTo;

            newEntry.newEntry = false;

            translations.push_back( newEntry );
        }


    }

    configFile.close();

    return populateNTerminals();
}

TranslationEntry TranslationDictionary::findTranslationFromNTerminal( NonTerminals NTerminalToFind )
{
    TranslationEntry output = TranslationEntry();

    for( auto & translation : translations )
    {
        if( translation.nTerminal == NTerminalToFind )
        {
            output = translation;
        }
    }

    return output;
}

/**
 * Private method to populate the translation entries with their proper NTerminal
 * @return If the population was successful.
 */
bool TranslationDictionary::populateNTerminals()
{
    auto it = vitalTranslations.begin();

    while( it != vitalTranslations.end() )
    {
        std::string currentNTerminalVal = it->first;

        NTerminal currentNTerminal = it->second;

        bool populated = assignTranslation( currentNTerminalVal, currentNTerminal );

        //if a vitalTranslation wasn't populated
        if( !populated )
        {
            //TODO: Log vital translation not being populated

            return false;
        }
        //increment the iterator for the next vital translation
        it++;

    }
    auto nonVitalIt = nonVital.begin();

    while( nonVitalIt != nonVital.end() )
    {
        std::string currentNTerminalVal = nonVitalIt->first;

        NTerminal currentNTerminal = nonVitalIt->second;

        bool populated = assignTranslation( currentNTerminalVal, currentNTerminal );

        if( !populated )
        {
            //TODO: Log if a non vital translation is missing
        }

        nonVitalIt++;
    }

    return true;
}

bool TranslationDictionary::assignTranslation(std::string translationString, NTerminal currentNTerminal )
{
    bool added = false;

    for( int index = 0; index < translations.size(); index++ )
    {
        if( translations[ index ].nTerminalVal == translationString )
        {
            translations[ index ].nTerminal = currentNTerminal;

            translations[ index ].translationAdded = true;

            added = true;
        }
    }

    return added;
}

/********************************
* Structure Support Code
*********************************/



/* Function: getStructName - Returns the name of
 * the struct held within a header declaration.
 *
 * Inputs:
 *
 *   std::string header - The header of the struct.
 *
 * Outputs: 
 *
 *   std::string header - The name of the struct.
 *
 * Precondition: A string containing a struct header provided.
 * Postcondition: Name of the struct parsed from the string and
 * returned. 
 *
 *
 */
std::string StructHandler::getStructName( std::string header )
{
    //trim open bracket
    header = header.substr( 0, header.find( "{" ) );

    // Trim whitespace
    header = stripWhiteSpace( header );

    auto firstStruct = header.find("struct" ) + 6;

    //gets only the struct name
    header = stripWhiteSpace( header.substr(firstStruct, header.size() - firstStruct) );

    return header;
}


/* Function: getVarName - Takes in a string
 * representing a symbolic declarartion. Finds
 * the variable name and returns to user.
 *
 * Inputs:
 *
 *   std::string decl - The symbolic declaration to parse.
 *
 * Outputs: 
 *
 *   std::string decl - The name of the variable in the
 *   symbolic declaration.
 *
 * Precondition: A string symbolic declaration provided.
 * Postcondition: Name of the variable in the string returned.
 *
 * Notes: This function only works for single variable declarations.
 * It will not work for Symbolic<int> a, b, c, d;
 */
std::string StructHandler::getVarName( std::string decl )
{
    // Trim whitespace from both sides of declaration and {
    decl = decl.substr( decl.find_first_not_of( " " ) , decl.size() - 1 );
    decl = decl.substr( 0, decl.find( ";" ) );

    // Trim any whitespace between the former ; and the name of the variable.
    decl = decl.substr( 0, decl.find_last_not_of( " " ) + 1 );

    // Eliminate Symbolic keyword.
    decl = decl.substr( decl.find_last_of( " " ) + 1, decl.size() );

    return decl;
}

std::string StructHandler::getTypeName( std::string decl )
{
    // Trim whitespace from both sides of declaration and {
    decl = decl.substr( decl.find_first_not_of( " " ) , decl.size() - 1 );
    decl = decl.substr( 0, decl.find( ";" ) );

    // Trim any whitespace between the former ; and the name of the variable.
    decl = decl.substr( 0, decl.find_last_not_of( " " ) + 1 );

    // Eliminate Symbolic keyword.
    decl = decl.substr( 0, decl.find_last_of( " " ) );

    return decl;
}



/* Function: structInList - Takes in a name
 * of a datatype and determines whether it references
 * a struct presently in the list with a symbolic parameter. 
 *
 * Inputs:
 *
 *   std::string name - The name of the declaration datatype.
 *
 * Outputs: 
 *
 *   Bool true/false - True if present, false otherwise.
 *
 */
bool StructHandler::structInList( std::string name )
{
    for( int index = 0; index < (int) this->structList.size(); index++ )
    {
        if( name.compare( structList.at( index ).getName() ) == 0 )
        {
            return true;
        }
    }

    return false;
} 


/* Function: assemblePacket - Takes a node and
 * an Assembly Code; packages StructPacket based
 * on code provided.
 *
 * Inputs:
 *
 *   Node declNode - The current node in the struct.
 * 
 *   AssemblyCode command - The operation to perform with the node.
 * 
 * Outputs: 
 *
 *   StructPacket packet - The packet of the currently held Struct. 
 *
 */
StructPacket StructHandler::assemblePacket( Node declNode, AssemblyCode command )
{
    // Declare local variables.
    static StructPacket packet;
    
    if( command == CLEAR_CURRENT )
    {
        // Add packet to the list.
        this->structList.push_back( packet );

        // Create new packet.
        StructPacket newPacket, tempPacket;
        tempPacket = packet;
        packet = newPacket;

        return tempPacket;
    }
    else if( command == ADD_VAR )
    {
        // Create new variable packet.
        VariablePacket newVar;

        // Configure newVar
        newVar.setVarName( getVarName( declNode.text ) );
        newVar.setDatatype( declNode.datatype );

        // Add to struct.
        packet.addParam( newVar );

        return packet;
    }
    else
    {
        // Configure packet.
        packet.setName( getStructName( declNode.text ) );

        return packet;
    }
}


/* Function: lookForSymbolic - Takes in an ast structure,
 * representing the structures in a unit testing file.
 * Scans the file for any structures and stores appropriate
 * information about it if it contains a symbolic declarartion.
 *
 * Inputs:
 *
 *   std::vector<Node> ast - The ast containing the file structure.
 *
 * Outputs: 
 *
 *   Null
 *
 * Precondition: A populated AST provided to handler.
 * Postcondition: All information about relevant structs 
 * stored in object.
 *
 */
void StructHandler::lookForSymbolic( std::vector<Node> ast )
{
    // Declare local variables.
    bool structFlag = false;

    for( int index = 0; index < (int) ast.size(); index++ )
    {
        if( ast.at( index ).type == STRUCT || ast.at(index).type == TYPEDEF )
        { 
            // Set struct flag.
            structFlag = true;

            // Place relevant info in packet.
            assemblePacket( ast.at( index ), ASSEMBLE );
        }
        else if( structFlag && ( ast.at( index ).type == SYMBOLIC ||
                                 structInList( getTypeName( ast.at( index ).text ) ) ) )         
        {
            assemblePacket( ast.at( index ), ADD_VAR );
        }
        else if( structFlag && ast.at( index ).text.find( "};" ) 
                 != std::string::npos )
        {
            assemblePacket( ast.at( index ), CLEAR_CURRENT );

            // Reset struct flag.
            structFlag = false;
        }     
    }
}


StructPacket StructHandler::getPacket( std::string name )
{
    for( int index = 0; index < (int) this->structList.size(); index++ )
    {
        if( structList.at( index ).getName().compare( name ) == 0 )
        {
            return structList.at( index );
        }
    }
}


std::vector<std::string> StructHandler::writeStatementFor( Node declNode, BinaryIterator * it )
{
    std::vector<std::string> stringOutputs;

    if( this->structInList( this->getTypeName( declNode.text ) ) )
    {
        // Fetch packet for declNode.
        StructPacket packet = getPacket( this->getTypeName( declNode.text ) );
        
        // Assemble statement.
        std::vector<std::string> statements = assembleStatement( packet, it  );

        // Write statements.
        for( int index = 0; index < (int) statements.size(); index++ )
        {
            stringOutputs.push_back( this->getVarName( declNode.text ) + statements.at( index ) + "\n" );
        }
    }

    return stringOutputs;
}


std::vector<std::string> StructHandler::assembleStatement( StructPacket packet, BinaryIterator * it  )
{
    // Declare local variables.
    std::vector<std::string> returnStatements;
    std::string temp;
    SymbolicPacket symbolicData;
    
    for( int index = 0; index < packet.length(); index++ )
    {
        std::string datatype = packet.getVarAt( index ).getDatatype();

        if( this->structInList( datatype ) )
        {
            // Get packet associated with sub-variable.
            StructPacket packet = getPacket( datatype );
            
            // Get statements for that subpacket.
            std::vector<std::string> statements = assembleStatement( packet, it );
        
            for( int sIndex = 0; sIndex < (int) statements.size(); sIndex++ )
            {
                returnStatements.push_back( "." + packet.getVarAt( index ).getName() + statements.at( sIndex ) );
            }                                   
        }

        else
        {

            // Fetch symbolic value.
            symbolicData.fetchSymbolic( datatype, it );

            // Obtain value from packet.
            auto packetData = symbolicData.getInt() * ( datatype.compare( "int" ) == 0 ) +
                              symbolicData.getUInt8() * ( datatype.compare( "uint8_t" ) == 0 ) +
                              symbolicData.getUInt16() * ( datatype.compare( "uint16_t" ) == 0 ) +
                              symbolicData.getUInt32() * ( datatype.compare( "uint32_t" ) == 0 ) +
                              symbolicData.getUInt64() * ( datatype.compare( "uint64_t" ) == 0 ) +
                              symbolicData.getShort() * ( datatype.compare( "short" ) == 0 ) +
                              symbolicData.getLong() * ( datatype.compare( "long" ) == 0 ) +
                              symbolicData.getInt() * ( datatype.compare( "unsigned" ) == 0 ) +
                              symbolicData.getChar() * ( datatype.compare( "char" ) == 0 );
                              //TODO Implement string functionality.

            returnStatements.push_back( "." + packet.getVarAt( index ).getName() + " = " + 
                                        std::to_string( packetData ) + ";" );

        }
    }

    return returnStatements;
}

std::vector<std::string> StructHandler::getStructNames()
{
    std::vector<std::string> structNames;

    auto currentStruct = structList.begin();

    while( currentStruct != structList.end() )
    {
        structNames.push_back( currentStruct->getName() );

        currentStruct++;
    }

    return structNames;
}


/********************************
* Symbolic Packet Code
*********************************/

SymbolicPacket::SymbolicPacket()
{
    this->uint8 = 0;
    this->uint16 = 0;
    this->uint32 = 0;
    this->uint64 = 0;
    this->integer = 0;
    this->flt = 0;
    this->dbl = 0;
    this->shrt = 0;
    this->lng = 0;
    this->character = 0;
    this->boolean = -1;
    this->string = ""; 
}


uint8_t SymbolicPacket::getUInt8()
{
    return this->uint8;
}


uint16_t SymbolicPacket::getUInt16()
{
    return this->uint16;
}

uint32_t SymbolicPacket::getUInt32()
{
    return this->uint32;
}

uint64_t SymbolicPacket::getUInt64()
{
    return this->uint64;
}

int SymbolicPacket::getInt()
{
    return this->integer;
}

float SymbolicPacket::getFloat()
{
    return this->flt;
}


double SymbolicPacket::getDouble()
{
    return this->dbl;
}

short SymbolicPacket::getShort()
{
    return this->shrt;
}

long SymbolicPacket::getLong()
{
    return this->lng;
}

char SymbolicPacket::getChar()
{
    return this->character;
}

bool SymbolicPacket::getBool()
{
    return this->boolean;
}

std::string SymbolicPacket::getString()
{
    return this->string;
}

void SymbolicPacket::fetchSymbolic( std::string datatype, BinaryIterator * it )
{
    
    
    if( datatype.compare( "int" ) == 0 )
    {
        this->integer = it->nextInt();
    }
    else if( datatype.compare( "uint8_t" ) == 0 )
    {
        this->uint8 = (uint8_t) it->nextInt();
    }
    else if( datatype.compare( "uint16_t" ) == 0 )
    {
        this->uint16 = (uint16_t) it->nextInt();
    }
    else if( datatype.compare( "uint32_t" ) == 0 )
    {
        this->uint32 = (uint8_t) it->nextInt();
    }
    else if( datatype.compare( "uint64_t" ) == 0 )
    {
        this->uint64 = (uint8_t) it->nextInt();
    }
    else if( datatype.compare( "short" ) == 0 )
    {
        this->shrt = it->nextShort();
    }
    else if( datatype.compare( "long" ) == 0 )
    {
        this->lng = it->nextLong();
    }
    else if( datatype.compare( "double" ) == 0 )
    {
        this->dbl = it->nextDouble();
    }
    else if( datatype.compare( "float" ) == 0 )
    {
        this->flt = it->nextFloat();
    }
    else if( datatype.compare( "char" ) == 0 )
    {
        this->character = it->nextChar();
    }
    else if( datatype.compare( "unsigned" ) == 0 )
    {
        this->integer = it->nextUInt();
    }
    else if( datatype.compare( "bool" ) == 0 )
    {
        this->boolean = it->nextBool();
    }
}


/********************************
* Variable Packet Code
*********************************/



/* Function: setVarName - Takes in a name for the variable
 * object and saves it in the packet. 
 *
 * Inputs:
 *
 *   std::string name - The name of the variable.
 *
 * Outputs: 
 *
 *   Null
 *
 * Precondition: A string name provided for the packet.
 * Postcondition: The string name provided is stored in the
 *                VariablePacket object for later reference.
 *
 *
 */
void VariablePacket::setVarName( std::string name )
{
    this->name = name;
}


/* Function: setDatatype - Takes in a datatype for the variable
 * object and saves it in the packet. 
 *
 * Inputs:
 *
 *   std::string datatype - The datatype of the variable.
 *
 * Outputs: 
 *
 *   Null
 *
 * Precondition: A string datatype provided for the packet.
 * Postcondition: The string datatype provided is stored in the
 *                VariablePacket object for later reference.
 *
 *
 */
void VariablePacket::setDatatype( std::string datatype )
{
    this->datatype = datatype;
}


/* Function: getName - Returns the name of the
 * variable held within the VariablePacket object.
 *
 * Inputs:
 *
 *   null
 *
 * Outputs: 
 *
 *   std::string name - The name of the variable.
 *
 * Precondition: N/A
 * Postcondition: The string name of the variable is 
 * returned or empty string if none has been provided.
 *
 *
 */
std::string VariablePacket::getName()
{
    return this->name;
}


/* Function: getDatatype - Returns the datatype
 * of the variable.
 *
 * Inputs:
 *
 *   Null
 *
 * Outputs: 
 *
 *   std::string datatype - The datatype of the variable.
 *
 * Precondition: N/A
 * Postcondition: The datatype of the variable returned
 * or empty string if none has been provided.
 *
 *
 */
std::string VariablePacket::getDatatype()
{
    return this->datatype;
}



/********************************
* Structure Packet Code
*********************************/




/* Function: setName - Takes in a name for the struct
 * object and saves it in the packet. 
 *
 * Inputs:
 *
 *   std::string name - The name of the struct.
 *
 * Outputs: 
 *
 *   Null
 *
 * Precondition: A string name provided for the packet.
 * Postcondition: The string name provided is stored in the
 *                StructPacket object for later reference.
 *
 *
 */
void StructPacket::setName( std::string name )
{
    this->name = name;
}


/* Function: addParam - Takes in a VariablePacket
 * object representing a new symbolic variable
 * found in the structure. 
 *
 * Inputs:
 *
 *   VariablePacket packet - The packet containing
 *   all relevant info of the variable.
 *
 * Outputs: 
 *
 *   Null
 *
 * Precondition: A fully configured VariablePacket provided.
 * Postcondition: The VariablePacket provided is stored in the
 *                StructPacket object below any others 
 *                for later reference.
 *
 *
 */
void StructPacket::addParam( VariablePacket &packet )
{
    this->varList.push_back( packet );
}


/* Function: getName - Returns the name of 
 * the struct.
 *
 * Inputs:
 *
 *   Null
 *
 * Outputs: 
 *
 *   std::string name - The name of the struct object 
 *   stored in the packet.
 *
 * Precondition: N/A
 * Postcondition: The string name held within the object
 *                returned or empty string if none present.
 *
 *
 */
std::string StructPacket::getName()
{
    return this->name;
}


/* Function: getVarAt - Takes in the index of the variable
 * to retrieve from the struct (variables are recorded in
 * linear order) and returns an object to the VariablePacket associated
 * with this variable. 
 *
 * Inputs:
 *
 *   int index - The index of the variable to retrieve.
 *
 * Outputs: 
 *
 *   VariablePacket * variable - The the variable
 *   at the position index in the struct.
 *
 * Precondition: Index is within the struct bounds.
 * Postcondition: The object of the requested variable
 * is returned or NULL.
 *
 *
 */
VariablePacket StructPacket::getVarAt( int index )
{
    if( index < (int) this->varList.size() )
    {
        return this->varList.at( index );
    }
}


/* Function: length - Returns the length of
 * the variable list held within the struct.
 *
 * Inputs:
 *
 *   Null
 *
 * Outputs: 
 *
 *   size_t varList.size() - The size of the internal
 *   varList vector.
 *
 * Precondition: N/A
 * Postcondition: Size of the vector returned.
 *
 *
 */
size_t StructPacket::length()
{
    return varList.size();
}


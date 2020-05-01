/**
  * @file FileAssembler.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief This will handle the reassembly of the standalone test
  *
  * @details This file will take in the output from the Translation Engine
  *          and utilize the binary parser to insert and generate a standalone test
  *
  * @version 1.00
  *          Tristan Miller ( 24 February 2019 )
  *          Began work on final system

  (Legal terms of use/libraries used need to be added here once we get to that point)

**/
#include "FileAssembler.h"

std::string buildFile( std::vector<Node> transEngineOutput, std::vector<std::string> binaryFiles,
        const char * outputPath, const char * translateCFG, bool basic_fuzz, bool fuzz_until_fail,
	std::string test_case )
{
    // Variable declarations.

    // Map of all translation targets available from CFG file.
    std::map<std::string, std::string> varMap;

    // The file write string that is populated in the file.
    std::string output;

    // Flags for various, important test structures.
    bool structFlag = false, testFlag = false, prevQuestion = false, loopFlag = false;

    // Counter to track the current test being run for the BinaryController.
    int testCounter = 0;

    // Object declarations for necessary classes.
    BinaryParser bp;
    BinaryController ctr;
    BinaryIterator it = bp.getIterator();
    ResultPacket results;
    TranslationDictionary translate;
    StructHandler handler;
    LoopHandler loopHandle( &ctr );
    std::string loopParams;
    std::string loopText;

    // Start the controller for proper value playback. 
    ctr.setTest( test_case );      
    ctr.fuzz_file( START_CONTROLLER );

    // Declare symbolic generator
    SymbolicGenerator generator( &ctr, &it, results, ( basic_fuzz || fuzz_until_fail ) );

    // Parse structs if they exist. 
    handler.lookForSymbolic( transEngineOutput );

    // If the CFG file is incorrect, error.
    if( !translate.loadFile(translateCFG) )
    {
        std::cout<<"Bad Load\n";

        //TODO: Log if loading the file is bad
    }

    // Get necessary values for loop.
    auto current = transEngineOutput.begin();
    auto size = transEngineOutput.size();
    int currentDepth = 0;

    for( int currentTranslation = 0; currentTranslation < (int) size; currentTranslation++ )
    {
        // Declare loop variables.
        bool added = false, currentQuestion = false;
        std::vector<std::string> stringsToAdd;

        // Get current String
        std::string currentString = stripWhiteSpace( current->text );
        currentString = stripNewLine( currentString );

        //Workaround for TE occasionally adding an additional blank line
        if( currentString.length() == 0 )
        {
            current++;

            continue;
        }

        //translate the deepstate include statement
        if( current->type == INCLUDE && current->text.find( INCLUDE_STATEMENT ) != std::string::npos )
        {
            added = true;

            output += generatePadding( currentDepth ) + translate.findTranslationFromNTerminal(INCLUDE).translateTo + '\n';
        }
        else if( current->type == STRUCT || current->type == TYPEDEF )
        {
            structFlag = true;

            added = true;

            output += generatePadding( currentDepth ) + currentString + "\n";
        }
        else if( current->type == SYMBOLIC && structFlag )
        {
            auto startOfVar = currentString.find_first_of(' ') + 1;

            auto location = currentString.find(',');

            std::string variableName = currentString.substr( startOfVar, location - startOfVar );

            output += generatePadding( currentDepth ) + current->datatype + " " + variableName + "\n";

            added = true;
        }
        else if( current->type == SYMBOLIC && loopFlag )
        {
            added = true;

            loopHandle.addType( current->datatype );
            output += generatePadding( currentDepth ) +  
                      loopHandle.writeSymbolicStatement( current->datatype, 
                                                         current->text,
                                                         loopText );
        }
        else if( current->type == SYMBOLIC && !loopFlag  )
        {
            added = true;

            stringsToAdd = symbolicValHandle( currentString, generator, current->datatype );
        }

        //handle ASSERT/CHECK/ASSUME statements
        else if( current->type >= ASSERT_GT && current->type <= CHECK )
        {
            added = true;

            currentQuestion = true;

            stringsToAdd = questionHandle( &translate, current->type, currentString );
        }
        //handles deepstate_question
        else if( current->type >= DEEPSTATE_ASSERT && current->type <= DEEPSTATE_CHECK )
        {
            added = true;

            currentQuestion = true;

            stringsToAdd = deepstateQuestionHandle( &translate, currentString );
        }
        else if( current->type >= DEEPSTATE_INT && current->type <= DEEPSTATE_BOOL )
        {
            added = true;

            stringsToAdd = deepstateTypeHandle( currentString, &it, &(*current) );
            
        }

        //get rid of namespace
        else if( currentString.find("using namespace deepstate;") != std::string::npos )
        {
            stringsToAdd.emplace_back("" );

            added = true;
        }
        //if a function has a NO_INLINE
        else if( current->type >= DEEPSTATE_NO_INLINE && current->type <= DEEPSTATE_NO_RETURN )
        {
            auto translation = translate.findTranslationFromNTerminal(current->type );

            if( translation.newEntry )
            {
                //TODO: Log this
                std::cout<<"Translation in line " + currentString + " is not found\n";
            }
            else
            {
                stringsToAdd.push_back( translate.findTranslationFromNTerminal(current->type ).translateTo +
                              currentString.substr( translation.nTerminalVal.length() - 1 ) + "\n" );
            }

            added = true;
        }
        //checking for struct declarations
        else if( !structFlag && testFlag && current->type == NO_TRANSLATE )
        {
            stringsToAdd = structHandle( currentString, &handler, &(*current), generator );
      
            added = !stringsToAdd.empty();
        }
        else if( current->type == END_OF_FILE )
        {
            added = true;
        }

        //statements used to handle when there is extra information after a question statement
        if( prevQuestion )
        {
            if( added )
            {
                output += ";\n";
            }
            else
            {
                //next statement must start with <<
                auto firstTwo = currentString.substr(0,2);

                if( firstTwo.find("<<") != std::string::npos )
                {
                    output += "\n";

                    if( currentString.find(';') == std::string::npos )
                    {
                        stringsToAdd.push_back( generatePadding(2) + currentString );

                        currentQuestion = true;
                    }
                    else
                    {
                        stringsToAdd.push_back( generatePadding(2) + currentString + "\n" );
                    }

                    added = true;
                }
                else
                {
                    output += ";\n";
                }
            }
        }

        if( current->text.find('}') != std::string::npos )
        {
            currentDepth--;

            if( currentDepth == 0 )
            {
                structFlag = false;

                testFlag = false;
            }
        }

        if( added )
        {
            auto addStrings = stringsToAdd.begin();

            while( addStrings != stringsToAdd.end() )
            {
                output += generatePadding( currentDepth ) + (*addStrings);

                addStrings++;
            }
        }
        else
        {
            output += generatePadding( currentDepth ) + currentString + "\n";
        }

        //if at the end of a function, add an additional new line
        if( currentDepth == 0 && currentString.find('}') != std::string::npos )
        {
            output += '\n';
        }

        if( current->text.find('{') != std::string::npos )
        {
            currentDepth++;
        }

        if( current->type == LOOP && !loopFlag )
        {
            loopFlag = true;
            loopHandle.setPos( (int) output.size() - (int) current->text.size() );
            loopText = current->text;
        }
        
        if( current->type == LOOP && loopFlag )
        {
            loopText = current->text;
        }
            
        if( current->text.find( "}" ) != std::string::npos )
        {
            loopFlag = false;
        }

        if( testCounter > 0 && ( current->type == TEST || current->type == END_OF_FILE )
	        && loopHandle.outputPos > 0 )
        {	
            output.insert( loopHandle.outputPos, 
                           loopHandle.writeSymbolicParams( results, generatePadding( currentDepth + 1 ) ) ); 
        }

        //reset the iterator for each test
        if( current->type == TEST )
        {
            // Reset controller.
            ctr.fuzz_file( RESET );

	        // Increment test counter.
	        generator.testCount++;
   
            if( basic_fuzz && fuzz_until_fail && ( generator.atTest() || !ctr.testInit() ) )
            {
                results = ctr.fuzz_file( FUZZ_UNTIL_FAIL, testCounter );
            }
            if( basic_fuzz && ( generator.atTest() || !ctr.testInit() ) )
            {
                results = ctr.fuzz_file( FUZZ_ONCE, testCounter );
            }
            else if( !( basic_fuzz && fuzz_until_fail ) )
            {
		        if( !ctr.testInit() || generator.atTest() )
		        {
                    generator.setIterator( binaryFiles );
                }
            }

            // Increment test counter.
            testCounter++;

            // Set test flag.
            testFlag = true;
        }

        prevQuestion = currentQuestion;

        current++;
    }

    //will insert a main function from the .cfg if it exists.
    auto mainTrans = translate.findTranslationFromNTerminal(MAIN_FUNC);

    if( mainTrans.translationAdded )
    {
        output += mainTrans.translateTo;
    }

    writeToFile( outputPath, output );

    return output;
}



std::string deepstateTypeReturn( Node currentNode, std::string currentString, BinaryIterator * it )
{
    std::string outputStr = " ";

    if( currentNode.type == DEEPSTATE_INT )
    {
        outputStr += std::to_string( it->nextInt() );
    }
    else if( currentNode.type == DEEPSTATE_UINT8 )
    {
        //TODO: Add UInt8 to iterator
    }
    else if( currentNode.type == DEEPSTATE_UINT16 )
    {
        outputStr += std::to_string( it->nextUInt16() );
    }
    else if( currentNode.type == DEEPSTATE_UINT32 )
    {
        //TODO: Add UInt32 to iterator
    }
    else if( currentNode.type == DEEPSTATE_UINT64 )
    {
        outputStr += std::to_string( it->nextUInt64() );
    }
    else if( currentNode.type == DEEPSTATE_DOUBLE )
    {
        outputStr += std::to_string( it->nextDouble() );
    }
    else if( currentNode.type == DEEPSTATE_USHORT )
    {
        //TODO: Add UShort to iterator
    }
    else if( currentNode.type == DEEPSTATE_UCHAR )
    {
        outputStr += std::to_string( it->nextUChar() );
    }
    else if( currentNode.type == DEEPSTATE_C_STR )
    {
        auto startOfFirst = currentString.find_first_of('(');

        auto end = questionClosingParen( currentString );

        std::string args = currentString.substr(startOfFirst+1, end-startOfFirst-1);

        auto comma = commaLocation(args);

        long firstArg = std::stol(args.substr(0, comma));

        std::string secondArg = args.substr(comma+1, end-comma-1);

        secondArg = stripWhiteSpace(secondArg);

        if(secondArg == "0")
        {
            outputStr += "\"" + it->nextString(firstArg, 0 ) + "\"";
        }
        else
        {
	    const char * character = secondArg.c_str();
            outputStr += "\"" + it->nextString(firstArg, character ) + "\"";
        }
    }
    else if( currentNode.type == DEEPSTATE_C_STRUPTO )
    {
        //TODO: Implement this
    }
    else if( currentNode.type == DEEPSTATE_MALLOC )
    {
        //TODO: Implement this
    }

    else
    {
        std::cout<<"UNIMPLEMENTED TYPE: " + currentNode.datatype;
    }

    return outputStr + ';';
}

std::string questionConversion( std::string previousText, NTerminal currentNTerminal, TranslationDictionary * dictionary )
{
    NTerminal baseCase = findBaseCase( currentNTerminal );

    std::string whichCheck;

    std::string translateTo = dictionary->findTranslationFromNTerminal(baseCase).translateTo;

    //Something changed and now there is occasionally whitespace where there shouldn't be, added this line to fix
    previousText = stripWhiteSpace( previousText );

    if( baseCase == CHECK )
    {
        whichCheck = questionWhichCheck( previousText, "CHECK_" );
    }
    else if( baseCase == ASSUME )
    {
        whichCheck = questionWhichCheck( previousText, "ASSUME_" );
    }
    else whichCheck = questionWhichCheck( previousText, "ASSERT_" );

    const auto& checkSign = checkCoversion.at(whichCheck);

    auto start = previousText.find_first_of('(');

    auto end = questionClosingParen( previousText );

    auto args = previousText.substr( start+1, end-start-1);

    auto comma = commaLocation( args );

    std::string firstArg = stripWhiteSpace( args.substr(0, comma ));

    std::string secondArg = stripWhiteSpace( args.substr(comma + 1, args.length() - comma ) );

    std::string output = translateTo + "( " + firstArg + ' ' + checkSign + ' ' + secondArg + " )";

    return output;
}

std::string questionTranslation( const TranslationEntry& translation, const std::string& originalString )
{
    std::string translateTo = translation.translateTo;

    auto start = originalString.find_first_of('(');

    auto end = originalString.find_last_of(';');

    auto values = originalString.substr( start, end - start );

    return translateTo + values;
}

int questionClosingParen( const std::string& args )
{
    auto cstr = args.c_str();

    int scopeCount = 0;

    int index;

    for( index = 0; index < args.size(); index++ )
    {
        char currentVal = cstr[index];

        if( currentVal == '(' )
        {
            scopeCount++;
        }
        else if( currentVal == ')' )
        {
            scopeCount--;

            //if last closing parentheses in args, but not later values
            if( scopeCount == 0 )
            {
                return index;
            }
        }
    }

    return index;
}

std::string questionWhichCheck( const std::string& toCheck, const std::string& baseCase )
{
    auto length = baseCase.length();

    return toCheck.substr(length, 2);
}


std::vector<std::string> symbolicValHandle( std::string currentString, SymbolicGenerator generator, 
                                            std::string &datatype )
{
    // Declare local variables.
    std::vector<std::string> outputVector;

    //if multi variable line
    while( currentString.find(',') != std::string::npos )
    {
        // Get basic locations and names
        auto startOfVar = currentString.find_first_of(' ') + 1;
        auto location = currentString.find(',');
        std::string variableName = currentString.substr( startOfVar, location - startOfVar );

        // Push to back of output vector
        outputVector.push_back( generator.writeSymbolicLine( variableName, datatype ) + "\n" );

        auto firstPart = currentString.substr( 0, startOfVar );
        auto secondPart = currentString.substr(location + 1, currentString.length() - location );

        //strip additional spaces
        while( secondPart.substr(0,1).find(' ') != std::string::npos )
        {
            secondPart = secondPart.substr(1, secondPart.length() - 1 );
        }

        currentString = firstPart + secondPart;
    }

    //locate the variable name
    auto startOfVar = currentString.find_last_of(' ') + 1;
    auto endOfVar = currentString.find(';');
    std::string variableName = currentString.substr(startOfVar, endOfVar - startOfVar );

    // Push created string
    outputVector.push_back( generator.writeSymbolicLine( variableName, datatype ) + '\n' );

    return outputVector;
}

std::vector<std::string> questionHandle( TranslationDictionary * translate, NTerminal current, const std::string& currentString )
{
    std::vector<std::string> outputVector;

    TranslationEntry translation = translate->findTranslationFromNTerminal( current );

    //If translation doesnt exist, convert to base case with the correct sign
    if( translation.newEntry )
    {
        outputVector.push_back( questionConversion(currentString, current, translate ) );
    }
    else
    {
        outputVector.push_back(questionTranslation(translation, currentString ) );
    }

    return outputVector;
}

std::vector<std::string> deepstateQuestionHandle( TranslationDictionary * translate, const std::string& currentString )
{
    std::vector<std::string> outputVector;

    auto startOfStatement = currentString.find_first_of('_') + 1;

    auto statement = currentString.substr(startOfStatement, currentString.length() - startOfStatement);

    NTerminal currentType;

    if( statement.find("Assume") != std::string::npos )
    {
        currentType = ASSUME;
    }
    else if( statement.find("Assert") != std::string::npos )
    {
        currentType = ASSERT;
    }
    else
    {
        currentType = CHECK;
    }

    auto translation = translate->findTranslationFromNTerminal( currentType );

    outputVector.push_back( questionTranslation( translation, statement ) );

    return outputVector;
}

std::vector<std::string> deepstateTypeHandle( const std::string& currentString, BinaryIterator * it, Node * current )
{
    std::vector<std::string> outputVector;

    auto equals = currentString.find('=') + 1;

    std::string line = currentString.substr(0, equals);

    std::string args = currentString.substr(equals, currentString.length() - equals );

    outputVector.push_back( line + deepstateTypeReturn( *current, stripWhiteSpace(args), it) + '\n' );

    return outputVector;
}

std::vector<std::string> structHandle( const std::string& currentString, StructHandler * handler, Node * current, 
			 	       SymbolicGenerator &generator )
{
    std::vector<std::string> outputVector;

    //search for struct name in current structs
    std::string structSearch = whichStructInLine( currentString, handler->getStructNames() );

    if( structSearch.size() != 0 )
    {
        outputVector.push_back( currentString + "\n" );

        auto strings = handler->writeStatementFor( (*current), generator );

        auto currentLine = strings.begin();

        while(currentLine != strings.end() )
        {
            outputVector.push_back( ( *currentLine++ ) );
        }
    }

    return outputVector;
}

NTerminal findBaseCase( NTerminal currentCase )
{
    if( currentCase >= ASSERT_GT && currentCase < ASSERT )
    {
        return ASSERT;
    }
    else if( currentCase >= ASSUME_GT && currentCase < ASSUME )
    {
        return ASSUME;
    }
    else return CHECK;
}

void writeToFile( const std::string& fileLocation, const std::string& fileContents )
{
    std::ofstream outputFile;

    outputFile.open( fileLocation );

    outputFile<<fileContents<<std::endl;

    outputFile.close();
}



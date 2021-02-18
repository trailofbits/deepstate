/**
  * @file FileAssembler.h
  *
  * @team GenTest ( Team 22 )
  *
  * @brief Header for File Assembler
  *
  *
  * @version 1.00
  *          Tristan Miller ( 24 February 2019 )
  *          Began work on final system

  (Legal terms of use/libraries used need to be added here once we get to that point)

**/

#include "DataStructures.h"
#include "LoopHandler.h"
#include "StructHandler.h"
#include <algorithm>

std::string buildFile( std::vector<Node> transEngineOutput, std::vector<std::string> binaryFile,
        const char * outputPath, const char * translateCFG, bool basic_fuzz, bool fuzz_until_fail,
	std::string test_case );

BinaryIterator * getIterator( std::vector<std::string> binaryFiles );

std::string symbolicLine( const std::string& variableName, BinaryIterator * iterator, BinaryController& ctr, ResultPacket packet, const std::string& type, bool fuzzFlag );

std::string deepstateTypeReturn( Node currentNode, std::string currentString, BinaryIterator * it  );

std::string questionConversion( std::string previousText, NTerminal currentNTerminal, TranslationDictionary * dictionary );

std::string questionTranslation( const TranslationEntry& translation, const std::string& originalString );

int questionClosingParen( const std::string& args );

std::vector<std::string> symbolicValHandle( std::string currentString, SymbolicGenerator generator, std::string &datatype );

std::vector<std::string> questionHandle(TranslationDictionary * translate, NTerminal current, const std::string& currentString );

std::vector<std::string> deepstateQuestionHandle( TranslationDictionary * translate, const std::string& currentString );

std::vector<std::string> deepstateTypeHandle( const std::string& currentString, BinaryIterator * it, Node * current );

std::vector<std::string> structHandle( const std::string& currentString, StructHandler * handler, Node * current, SymbolicGenerator &generator );

std::string questionWhichCheck( const std::string& toCheck, const std::string& baseCase );

NTerminal findBaseCase( NTerminal currentCase );

void writeToFile( const std::string& fileLocation, const std::string& fileContents );

std::string getLoopValues( BinaryIterator * iterator, BinaryController& ctr, 
                                        ResultPacket results, const std::string& type, bool fuzzFlag );

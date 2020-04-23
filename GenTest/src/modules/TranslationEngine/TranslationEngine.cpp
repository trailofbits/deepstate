// Program Information //////////////////////////////////////////////
/**
  * @file DataStructures.cpp
  *
  * @team GenTest ( Team 22 )
  *
  * @brief For deconstructing of DeepState tests into a context free grammar
  *
  * @details This class will be deconstruct DeepStates behaviours into a context-free grammar
  *          and store these values into a vector class. This vector class will then be sent
  *          to the File assembler for reconstruction into a standalone test
  *          For the Demo it shall be able to translate the following example test harnesses:
  *
  *          	o Crash.cpp
  *		        o Euler.cpp
  *		        o IntegerOverflow.cpp
  *		        o Primes.cpp 
  *
  * @version 0.15 
  *          Joshua Johnson( 31 January 2020 )
  *          Removed demo code from file, migrated code to use ANTLR version 4.8 parser
  *          for translation term identification.             
  *
  *          0.10
  *          Tristan Miller ( 13 January 2020 )
  *          Refactored demo code to be more inline with other styling
  *
  *          0.01
  *          Tristan Miller ( 5 November 2019 )
  *          Created skeleton for class layout
  *          
  *

 (Legal terms of use/libraries used need to be added here once we get to that point)

**/

#include "TranslationEngine.h"
#include "ASTListener.h"

using namespace std;
using namespace antlr4;


std::vector<Node> TranslationEngine::getAST( std::string fileName )
{
   // Open input file.
   std::ifstream stream;
   stream.open( fileName );

   // Open stream in ANTLR
   ANTLRInputStream input( stream );

   // Create lexer.
   GenTestLexer lexer( &input );

   // Create common tokens.
   CommonTokenStream tokens( &lexer );
   tokens.fill();

   // Create parser.
   GenTestParser parser( &tokens );

   // Create listener.
   ASTListener listener;

   antlr4::tree::ParseTree * tree = parser.file();
 
   antlr4::tree::ParseTreeWalker::DEFAULT.walk( &listener, tree );

   stream.close();

   return listener.getAST();

}



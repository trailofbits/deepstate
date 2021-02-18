// Program Header Information ///////////////////////////
/**
 * @file TranslationEngine.h
 *
 * @team GenTest ( Team 22 )
 *
 * @brief Header file for the TranslationEngine system
 *
 * @details Contains the interface for the TranslationEngine class, which is used to 
 *          provide interpretation features to the GenTest code base. 
 *
 * @version 0.15 
 *          Joshua Johnson ( 31 January 2020 )
 *          Removed demo functions, modified includes, and added TranslationEngine class.
 *          
 *          0.10
 *          Joshua Johnson ( 16 November 2019 )
 *          Initial development of the TranslationEngine
 */

#ifndef GENTEST_TRANSLATIONENGINE_H
#define GENTEST_TRANSLATIONENGINE_H


/******************************
* Included Files
*******************************/

#include "antlr4-runtime.h"
#include "GenTestLexer.h"
#include "GenTestParser.h"
#include "GenTestListener.h"
#include "DataStructures.h"
#include <fstream>
#include <iostream>
#include <string>


/******************************
* Class Definitions
*******************************/

using namespace antlr4;
using namespace std;

class TranslationEngine {

    antlr4::tree::ParseTree * tree;

    public:
    std::vector<Node> getAST( std::string fileName );
};



#endif //GENTEST_TRANSLATIONENGINE_H

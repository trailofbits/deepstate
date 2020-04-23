
// Program Header Information ///////////////////////////
/**
 * @file Util.h
 *
 * @team GenTest ( Team 22 )
 *
 * @brief Header file for Util
 *
 * @details Contains class and function definitions for Util.cpp
 *
 * @version 1.00
 *          Tristan Miller
 *          Created Skeleton File
 *
 */

#ifndef GENTEST_UTIL_H
#define GENTEST_UTIL_H

/******************************
* Include Libraries
*******************************/
#include <string>
#include <map>
#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <utility>

/******************************
* Constant Definitions
*******************************/

const std::string S_ASSERT = "ASSERT(";
const std::string S_ASSERT_GT = "ASSERT_GT";
const std::string S_ASSERT_LT = "ASSERT_LT";
const std::string S_ASSERT_GE = "ASSERT_GE";
const std::string S_ASSERT_LE = "ASSERT_LE";
const std::string S_ASSERT_EQ = "ASSERT_EQ";
const std::string S_ASSERT_NE = "ASSERT_NE";
const std::string S_ASSUME_GT = "ASSUME_GT";
const std::string S_ASSUME_LT = "ASSUME_LT";
const std::string S_ASSUME_GE = "ASSUME_GE";
const std::string S_ASSUME_LE = "ASSUME_LE";
const std::string S_ASSUME_EQ = "ASSUME_EQ";
const std::string S_ASSUME_NE = "ASSUME_NE";
const std::string S_CHECK_GT = "CHECK_GT";
const std::string S_CHECK_LT = "CHECK_LT";
const std::string S_CHECK_GE = "CHECK_GE";
const std::string S_CHECK_LE = "CHECK_LE";
const std::string S_CHECK_EQ = "CHECK_EQ";
const std::string S_CHECK_NE = "CHECK_NE";
const std::string S_DEEPSTATE_ASSERT = "DeepState_Assert";
const std::string S_DEEPSTATE_ASSUME = "DeepState_Assume";
const std::string S_DEEPSTATE_CHECK = "DeepState_Check";

const std::string S_DEEPSTATE_NOINLINE = "DEEPSTATE_NOINLINE";
const std::string S_TEST = "TEST";

const std::string SYMB_UNDER_INT = "symbolic_int";
const std::string SYMB_UNDER_UINT8 = "symbolic_uint8_t";
const std::string SYMB_UNDER_UINT16 = "symbolic_uint16_t";
const std::string SYMB_UNDER_UINT32 = "symbolic_uint32_t";
const std::string SYMB_UNDER_UINT64 = "symbolic_uint64_t";
const std::string SYMB_UNDER_LONG = "symbolic_long";
const std::string SYMB_UNDER_SHORT = "symbolic_short";
const std::string SYMB_UNDER_CHAR = "symbolic_char";
const std::string SYMB_UNDER_FLOAT = "symbolic_float";
const std::string SYMB_UNDER_DOUBLE = "symbolic_double";
const std::string SYMB_UNDER_UNSIGNED = "symbolic_unsigned";

const std::string SYMB_BRACKET_INT = "Symbolic<int>";
const std::string SYMB_BRACKET_UINT8 = "Symbolic<uint8_t>";
const std::string SYMB_BRACKET_UINT16 = "Symbolic<uint16_t>";
const std::string SYMB_BRACKET_UINT32 = "Symbolic<uint32_t>";
const std::string SYMB_BRACKET_UINT64 = "Symbolic<uint64_t>";
const std::string SYMB_BRACKET_LONG = "Symbolic<long>";
const std::string SYMB_BRACKET_SHORT = "Symbolic<short>";
const std::string SYMB_BRACKET_CHAR = "Symbolic<char>";
const std::string SYMB_BRACKET_FLOAT = "Symbolic<float>";
const std::string SYMB_BRACKET_DOUBLE = "Symbolic<double>";
const std::string SYMB_BRACKET_UNSIGNED = "Symbolic<unsigned>";

const std::string SYMBOLIC_BRACKETS = "Symbolic";
const std::string INCLUDE_STATEMENT = "DeepState.hpp";

// General Constants
const std::string EMPTY_STRING = "";
const std::string SPACE = " ";
const std::string SEMI_COLON = ";";
const std::string OPEN_PARENTHESIS = "(";
const std::string CLOSE_PARENTHESIS = ")";
const std::string OPEN_BRACKET = "{";
const std::string CLOSE_BRACKET = "}";
const std::string STRING_EQUALS;
const std::string LT_SYMB = "<";
const std::string GT_SYMB = ">";
const std::string UNDERSCORE = "_";
const std::string COMMA = ",";
const std::string TWO_SPACES = "  ";


std::string stripWhiteSpace( const std::string& toStrip );

std::string stripNewLine( std::string stringToStrip );

std::string generatePadding( int depth );

int commaLocation( const std::string& toFind );

std::string whichStructInLine(std::string lineToCheck, std::vector<std::string> vectorToSearch );



#endif //GENTEST_UTIL_H

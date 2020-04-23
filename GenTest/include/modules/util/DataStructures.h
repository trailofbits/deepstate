// Program Header Information ///////////////////////////
/**
 * @file DataStructures.h
 *
 * @team GenTest ( Team 22 )
 *
 * @brief Header File for DataStructures
 *
 * @details Contains Struct and Function Definitions for DataStructures.cpp
 *
 * @version 1.00
 *          Tristan Miller
 *          Created Skeleton File
 *
 */

#ifndef GENTEST_DATASTRUCTURES_H
#define GENTEST_DATASTRUCTURES_H

#include "Util.h"
#include "BinaryIterator.h"


//TranslationEngine structures
typedef enum NonTerminals
{
    ROOT = 0,
    FUNC,                     // Basic non-terminals.
    TEST,
    STATEMENT,
    LOOP,
    WHILE_LOOP,
    COMMENT,
    DEEPSTATE_NO_INLINE,
    DEEPSTATE_INLINE,
    DEEPSTATE_NO_RETURN,
    NO_TRANSLATE,
    NAMESPACE,
    INCLUDE,
    DEFINE,
    IF,
    ASSERT_GT,
    ASSERT_LT,
    ASSERT_GE,
    ASSERT_LE,
    ASSERT_NE,
    ASSERT_EQ,
    ASSERT,
    ASSUME_GT,
    ASSUME_LT,
    ASSUME_GE,
    ASSUME_LE,
    ASSUME_NE,
    ASSUME_EQ,
    ASSUME,
    CHECK_GT,
    CHECK_LT,
    CHECK_GE,
    CHECK_LE,
    CHECK_NE,
    CHECK_EQ,
    CHECK,
    DEEPSTATE_ASSERT,
    DEEPSTATE_ASSUME,
    DEEPSTATE_CHECK,
    DEEPSTATE_INT,
    DEEPSTATE_UINT8,
    DEEPSTATE_UINT16,
    DEEPSTATE_UINT32,
    DEEPSTATE_UINT64,
    DEEPSTATE_FLOAT,
    DEEPSTATE_DOUBLE,
    DEEPSTATE_USHORT,
    DEEPSTATE_UCHAR,
    DEEPSTATE_CHAR,
    DEEPSTATE_C_STR,
    DEEPSTATE_C_STRUPTO,
    DEEPSTATE_MALLOC,
    SYMBOLIC,
    CLOSE_BRK,
    OPEN_BRK,
    MAIN_FUNC,
    TYPEDEF,
    STRUCT

} NTerminal;

//Contains all translations required to run the program
const std::map < std::string, NonTerminals > vitalTranslations =
        {{"ASSERT", ASSERT},
         {"CHECK", CHECK},
         {"ASSUME", ASSUME},
         {"INCLUDE", INCLUDE}};

//Contains all translations not vital to run the program, but can still be used.
const std::map < std::string, NonTerminals > nonVital =
        {{"DEEPSTATE_NO_INLINE", DEEPSTATE_NO_INLINE},
         {"DEEPSTATE_INLINE", DEEPSTATE_INLINE},
         {"DEEPSTATE_NO_RETURN", DEEPSTATE_NO_RETURN},
         {"MAIN_FUNC", MAIN_FUNC},
         { "ASSERT_GT", ASSERT_GT },
         { "ASSERT_GE", ASSERT_GE },
         { "ASSERT_LT", ASSERT_LT },
         { "ASSERT_LE", ASSERT_LE },
         { "ASSERT_NE", ASSERT_NE },
         { "ASSERT_EQ", ASSERT_EQ },
         { "CHECK_EQ", CHECK_EQ },
         { "CHECK_NE", CHECK_NE },
         { "CHECK_LT", CHECK_LT },
         { "CHECK_LE", CHECK_LE },
         { "CHECK_GT", CHECK_GT },
         { "CHECK_GE", CHECK_GE },
         { "ASSUME_EQ", ASSUME_EQ },
         { "ASSUME_NE", ASSUME_NE },
         { "ASSUME_LT", ASSUME_LT },
         { "ASSUME_LE", ASSUME_LE },
         { "ASSUME_GT", ASSUME_GT },
         { "ASSUME_GE", ASSUME_GE }};

const std::map <std::string, std::string> checkCoversion =
        {{"GT", ">"},
        {"GE", ">="},
        {"LT", "<"},
        {"LE", "<="},
        {"NE", "!="},
        {"EQ", "=="}};


class Node {
	
    public:

    NTerminal type;
    std::string text;
    std::string datatype;
    std::vector<std::string> list;
};




/**
 * Helper class for TranslationDictionary, stores the desired translation
 */
class TranslationEntry
{
public:
    std::string nTerminalVal;

    NonTerminals nTerminal;

    std::string translateTo;

    bool newEntry = true;

    bool translationAdded = false;
};

/**
 * Class for storing translations loaded from a configuration file.
 */
class TranslationDictionary
{
public:
    bool loadFile( const std::string& filePath );

    TranslationEntry findTranslationFromNTerminal( NonTerminals NTerminalToFind );

private:
    std::ifstream configFile;
  
    std::vector< TranslationEntry > translations;

    bool populateNTerminals();

    bool assignTranslation(std::string translationString, NTerminal currentNTerminal );
};

class VariablePacket
{
    private:
        std::string name;
        std::string datatype;

    public:
        void setVarName( std::string name );
        void setDatatype( std::string datatype );
        std::string getName();
        std::string getDatatype();
};

class StructPacket
{
    private:
        std::string name;
        std::vector<VariablePacket> varList;

    public:

        void setName( std::string name );
        void addParam( VariablePacket &packet );
        std::string getName();
        size_t length();
        VariablePacket getVarAt( int index );
};

class SymbolicPacket
{
    private:
        uint8_t uint8;
        uint16_t uint16;
        uint32_t uint32;
        uint64_t uint64;
        int integer;
        float flt;
        double dbl;
        short shrt;
        long lng;
        char character;
        bool boolean;
        std::string string;

    public:
        
        SymbolicPacket();
        void fetchSymbolic( std::string datatype, BinaryIterator * it );  
        uint8_t getUInt8();
        uint16_t getUInt16();
        uint32_t getUInt32();
        uint64_t getUInt64();
        int getInt();
        float getFloat();
        double getDouble();
        short getShort();
        long getLong();
        char getChar();
        bool getBool();
        std::string getString(); 
};

        
class StructHandler 
{
    private:
        std::vector<StructPacket> structList;
        
        bool structInList( std::string name );
        StructPacket getPacket( std::string name );
        std::vector<std::string> assembleStatement( StructPacket packet, BinaryIterator * it  );
	
    
    public:

        typedef enum StructAssemblyCodes {

            ASSEMBLE = 0,
            ADD_VAR,
            CLEAR_CURRENT


        } AssemblyCode;

        std::string getStructName( std::string header );
        std::string getVarName( std::string decl );
        std::string getTypeName( std::string decl );
        StructPacket assemblePacket( Node declNode, AssemblyCode command );
        void lookForSymbolic( std::vector<Node> ast );
        std::vector<std::string> writeStatementFor( Node declNode, BinaryIterator * it );
        std::vector<std::string> getStructNames();
};

    
#endif //GENTEST_DATASTRUCTURES_H

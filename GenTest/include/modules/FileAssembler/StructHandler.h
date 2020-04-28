
/******************
* Include Files
*******************/
#ifndef STRUCTHANDLER_H
#define STRUCTHANDLER_H

#include "SymbolicGenerator.h"

/******************
* Class Definitions
*******************/

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
        std::string fetchSymbolic( std::string datatype, SymbolicGenerator &generator );
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
        std::vector<std::string> assembleStatement( StructPacket packet, SymbolicGenerator &generator  );
	
    
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
        std::vector<std::string> writeStatementFor( Node declNode, SymbolicGenerator &generator );
        std::vector<std::string> getStructNames();
};

#endif

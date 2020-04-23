
/******************
* Include Files
*******************/
#include "DataStructures.h"
#include "BinaryController.h"
#include "BinaryIterator.h"
#include "BinaryParser.h"

/******************
* Class Definitions
*******************/

class SymbolicGenerator
{
    private:
        BinaryController * ctr;
        BinaryIterator * it;
        ResultPacket results;
        bool fuzz;
        
        // Binary File Algorithms
        int getInt( BinaryIterator * it );
        unsigned int getUInt( BinaryIterator * it );
        int8_t getInt8( BinaryIterator * it );
        int16_t getInt16( BinaryIterator * it );
        int32_t getInt32( BinaryIterator * it );
        int64_t getInt64( BinaryIterator * it );
        uint8_t getUInt8( BinaryIterator * it );
        uint16_t getUInt16( BinaryIterator * it );
        uint32_t getUInt32( BinaryIterator * it );
        uint64_t getUInt64( BinaryIterator * it );
        short getShort( BinaryIterator * it );
        long getLong( BinaryIterator * it );
        double getDouble( BinaryIterator * it );
        float getFloat( BinaryIterator * it ); 
        char getChar( BinaryIterator * it );
        unsigned char getUChar( BinaryIterator * it );
        //std::string getString( BinaryIterator * it )

    public:

        SymbolicGenerator( BinaryController * ctr, BinaryIterator * it, 
                           ResultPacket &results, bool fuzz );

        SymbolicGenerator( BinaryController *& ctr, ResultPacket &results );

        void setIterator( std::vector<std::string> binaryFiles );

	BinaryIterator * getIterator();

        std::string getSymbolic( std::string datatype );

        std::string writeSymbolicLine( std::string varName, std::string datatype );
        
};


/*****************************
* Libraries
******************************/
#ifndef BINARYCONTROLLER_H
#define BINARYCONTROLLER_H
#include "TranslationEngine.h"
#include <deepstate/DeepState.h>


/*****************************
* Typedef Definitions
******************************/
typedef enum ControllerCommand
{
    FUZZ_ONCE = 0,
    FUZZ_UNTIL_FAIL,
    START_CONTROLLER,
    RESET

} ControllerCommand;


/*****************************
* Class Definitions
******************************/

class ResultPacket
{
    uint32_t bytes_read;
    DeepState_TestRunResult test_result;

    public:

        ResultPacket();
        void set_read_bytes( uint32_t bytes_read );
        void add_to_bytes( uint32_t bytes_read );
        void set_test_result( DeepState_TestRunResult result );
        uint32_t get_bytes();
        DeepState_TestRunResult get_result();
};

class BinaryController
{
    const unsigned FUZZ_MAX = 1000;
    unsigned int pos;
	std::string test_case;

    // Private functions
    ResultPacket fuzz_one_test( DeepState_TestInfo * test );
    ResultPacket fuzz_until_fail( DeepState_TestInfo * test );
	DeepState_TestInfo * getTest( int testIndex );

    public:

    unsigned int testIndex;

    BinaryController();
    ResultPacket fuzz_file( ControllerCommand command, int testIndex = 0 );

	unsigned int getPos();
	void setPos( unsigned int pos );
	void setTest( std::string test_case );

	// intx_t types
    int8_t getInt8();
	int16_t getInt16();
    int32_t getInt();
    int64_t getInt64();
	
	// uintx_t types
    unsigned int getUInt();
    uint64_t getUInt64();

	// Other numeric types.
    double getDouble();
    float getFloat();
    short getShort();
    unsigned short getUShort();
    long getLong();

	// Character types
    int8_t getChar();
    uint8_t getUChar();

	// Boolean types.
    bool getBool();
    
    bool testInit();
};

#endif

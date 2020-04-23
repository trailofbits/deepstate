
/*****************************
* Libraries
******************************/
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

    // Private functions
    ResultPacket fuzz_one_test( DeepState_TestInfo * test );
    ResultPacket fuzz_until_fail( DeepState_TestInfo * test );

    public:

        BinaryController();
        ResultPacket fuzz_file( ControllerCommand command, int testIndex = 0 );
	unsigned int getPos();
	void setPos( unsigned int pos );
        short getShort();
        uint16_t getUShort();
        int32_t getInt();
        int64_t getInt64();
        uint32_t getUInt();
        uint64_t getUInt64();
        double getDouble();
        float getFloat();
        int32_t getLong();
        int8_t getChar();
        uint8_t getUChar();
        bool getBool();
};



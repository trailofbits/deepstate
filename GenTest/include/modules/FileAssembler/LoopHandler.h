
#include "SymbolicGenerator.h"

// Global constants
const int ONE_BYTE = 1;
const int TWO_BYTES = 2;
const int FOUR_BYTES = 4;
const int EIGHT_BYTES = 8;


class LoopHandler
{
    private:

        bool multiType, createSymbolic;
	BinaryController * ctr;
        std::vector<std::string> typeManifest;
        std::string getLoopParams();
	bool isInManifest( std::string type );

    public:
	int outputPos;

        LoopHandler();
        LoopHandler( BinaryController * ctr );
        void addType( std::string type );
        void setPos( int pos );
        std::string writeSymbolicParams( ResultPacket &results );
        std::string writeSymbolicStatement( std::string datatype, std::string currentText, 
				            std::string loopText );
};

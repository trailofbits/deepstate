pragma solidity ^0.4.15;
contract DeepStateProperty {

    event ASSERT_LOG(bytes32 msg);
    function ASSUME_GT(uint x, uint y) internal {
        assert(x > y);
    }

    function ASSUME_GE(uint x, uint y) internal {
        assert(x >= y);
    }

    function ASSUME_LT(uint x, uint y) internal {
        assert(x < y);
    }

    function ASSUME_NE(uint x, uint y) internal {
        assert(x != y);
    }

    function ASSERT_LT(uint x, uint y, bytes32 msg) internal {
        if (!(x < y)) {
            ASSERT_LOG(msg);
            assert(false);
        }
    }

    function BOOL2UINT(bool x) internal returns (uint) {
        if (x)
            return 1;
        else
            return 0;
    }
}
contract TEST is DeepStateProperty {
    function Test_AdditionOverflow(uint x) public {
        uint y = x + x;
        ASSUME_GE(y, 0);
    }

    function Test_MultiplicationOverflow(uint x) public {
        uint y = x * x;
        ASSUME_GE(y, 0);
    }

}

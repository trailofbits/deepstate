contract DeepStateProperty {

    event ASSERT_LOG(bytes32 msg);
    function ASSUME_GT(uint x, uint y) internal {
        assert(x > y);
    }

    function ASSUME_GE(int x, int y) internal {
        assert(x >= y);
    }

    function ASSUME_LT(uint x, uint y) internal {
        assert(x < y);
    }

    function ASSUME_LE(uint x, uint y) internal {
        assert(x <= y);
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

    function ASSERT_GT(uint x, uint y, bytes32 msg) internal {
        if (!(x > y)) {
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

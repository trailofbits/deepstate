pragma solidity ^0.4.15;

import "examples/DeepState.sol";

contract TEST is DeepStateTest {
    function Test_SignedInteger_AdditionOverflow(int x) public {
        int y = x + x;
        ASSUME_GE(y, 0);
    }

    function Test_SignedInteger_MultiplicationOverflow(int x) public {
        int y = x * x;
        ASSUME_GE(y, 0);
    }

}

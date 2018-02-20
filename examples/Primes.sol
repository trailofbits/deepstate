import "examples/DeepState.sol";

contract TEST is DeepStateProperty {
   
    function IsPrime(uint p) internal returns (bool) { 
        uint i;
        for (i=2; i <= (p/2); ++i) {
            if ((p % i) == 0) 
                return false;
        }
        return true;
   
    } 

    function Test_PrimePolinomial_OnlyGeneratesPrimes(uint x, uint y, uint z) public {
        ASSUME_GT(x, 0);
        uint poly = (x * x) + x + 41;
        ASSUME_GT(y, 1);
        ASSUME_GT(z, 1);
        ASSUME_LT(y, poly);
        ASSUME_LT(z, poly);
        ASSERT_NE(poly, y * z, "x ** 2 + x + 41 is not prime");
        ASSERT( IsPrime(poly) ); 
    }
}


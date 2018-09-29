#include <deepstate/DeepState.hpp>

uint16_t Pow2(uint16_t x) {
  return x * x;
}

TEST(Math, PowersOfTwo) {
  ASSERT_EQ(Pow2(0), 0);  // 0^2 == 0
  ASSERT_NE(Pow2(2), 3);  // 2^2 != 3
  // Try some for yourself!
}

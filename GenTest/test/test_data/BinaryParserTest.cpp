#include <deepstate/DeepState.hpp>

using namespace deepstate;

DEEPSTATE_NOINLINE int ident1(int x) {
    return x;
}

DEEPSTATE_NOINLINE int ident2(int x) {
    return x;
}

TEST(GenerateValue, ValueGenerate) {
    Symbolic<int> x;

    ASSERT_GE(x, 0)
            << "The value " + std::to_string(x) + " was generated";
}


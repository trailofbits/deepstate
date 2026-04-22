#pragma once
#include <stdint.h>

typedef struct {
    uint32_t mwc_upper;
    uint32_t mwc_lower;
    uint32_t cong;
    uint32_t shr3;
} DeepStateRng;

static inline void deepstate_rng_seed(DeepStateRng *rng, uint32_t seed) {
    rng->mwc_upper = seed ^ 0x9e3779b9u;
    rng->mwc_lower = seed ^ 0x243f6a88u;
    rng->cong      = seed ^ 0xb7e15163u;
    rng->shr3      = seed ^ 0x71374491u;
    if (rng->shr3 == 0) rng->shr3 = 0xdeadbeef;
}

static inline uint32_t deepstate_rng_next(DeepStateRng *rng) {
    uint64_t mwc = (uint64_t)698769069u * rng->mwc_lower + rng->mwc_upper;
    rng->mwc_upper = (uint32_t)(mwc >> 32);
    rng->mwc_lower = (uint32_t)mwc;

    rng->cong = 69069u * rng->cong + 12345u;

    rng->shr3 ^= rng->shr3 << 13;
    rng->shr3 ^= rng->shr3 >> 17;
    rng->shr3 ^= rng->shr3 << 5;

    return rng->mwc_lower ^ rng->cong ^ rng->shr3;
}
#define HIGHWAYHASH_PORTABLE
#include "hh_c/highwayhash.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*////////////////////////////////////////////////////////////////////////////*/
/* Internal implementation                                                    */
/*////////////////////////////////////////////////////////////////////////////*/

void HighwayHashReset(HighwayHashState *restrict state,
                      const uint64_t *restrict key) {
  state->mul0[0] = 0xdbe6d5d5fe4cce2f;
  state->mul0[1] = 0xa4093822299f31d0;
  state->mul0[2] = 0x13198a2e03707344;
  state->mul0[3] = 0x243f6a8885a308d3;
  state->mul1[0] = 0x3bd39e10cb0ef593;
  state->mul1[1] = 0xc0acf169b5f18a8c;
  state->mul1[2] = 0xbe5466cf34e90c6c;
  state->mul1[3] = 0x452821e638d01377;
  for (int i = 0; i < 4; i++) {
    state->v0[i] = state->mul0[i] ^ key[i];
    state->v1[i] = state->mul1[i] ^ ((key[i] >> 32) | (key[i] << 32));
  }
}

void ZipperMergeAndAdd(const uint64_t v1, const uint64_t v0,
                       uint64_t *restrict add1, uint64_t *restrict add0) {
  *add0 += (((v0 & 0xff000000) | (v1 & 0xff00000000)) >> 24) |
           (((v0 & 0xff0000000000) | (v1 & 0xff000000000000)) >> 16) |
           (v0 & 0xff0000) | ((v0 & 0xff00) << 32) |
           ((v1 & 0xff00000000000000) >> 8) | (v0 << 56);
  *add1 += (((v1 & 0xff000000) | (v0 & 0xff00000000)) >> 24) | (v1 & 0xff0000) |
           ((v1 & 0xff0000000000) >> 16) | ((v1 & 0xff00) << 24) |
           ((v0 & 0xff000000000000) >> 8) | ((v1 & 0xff) << 48) |
           (v0 & 0xff00000000000000);
}

void Update(HighwayHashState *restrict state, const uint64_t *restrict lanes) {
  for (int i = 0; i < 4; ++i) {
    state->v1[i] += state->mul0[i] + lanes[i];
    state->mul0[i] ^= (state->v1[i] & 0xffffffff) * (state->v0[i] >> 32);
    state->v0[i] += state->mul1[i];
    state->mul1[i] ^= (state->v0[i] & 0xffffffff) * (state->v1[i] >> 32);
  }
  ZipperMergeAndAdd(state->v1[1], state->v1[0], &state->v0[1], &state->v0[0]);
  ZipperMergeAndAdd(state->v1[3], state->v1[2], &state->v0[3], &state->v0[2]);
  ZipperMergeAndAdd(state->v0[1], state->v0[0], &state->v1[1], &state->v1[0]);
  ZipperMergeAndAdd(state->v0[3], state->v0[2], &state->v1[3], &state->v1[2]);
}

uint64_t Read64(const uint8_t *restrict src) {
  return (uint64_t)src[0] | ((uint64_t)src[1] << 8) | ((uint64_t)src[2] << 16) |
         ((uint64_t)src[3] << 24) | ((uint64_t)src[4] << 32) |
         ((uint64_t)src[5] << 40) | ((uint64_t)src[6] << 48) |
         ((uint64_t)src[7] << 56);
}

void HighwayHashUpdatePacket(HighwayHashState *restrict state,
                             const uint8_t *restrict packet) {
  uint64_t lanes[4];
  lanes[0] = Read64(packet + 0);
  lanes[1] = Read64(packet + 8);
  lanes[2] = Read64(packet + 16);
  lanes[3] = Read64(packet + 24);
  Update(state, lanes);
}

void Rotate32By(uint64_t count, uint64_t lanes[4]) {
  for (int i = 0; i < 4; ++i) {
    uint32_t half0 = lanes[i] & 0xffffffff;
    uint32_t half1 = (lanes[i] >> 32);
    lanes[i] = (half0 << count) | (half0 >> (32 - count));
    lanes[i] |= (uint64_t)((half1 << count) | (half1 >> (32 - count))) << 32;
  }
}

void HighwayHashUpdateRemainder(HighwayHashState *restrict state,
                                const uint8_t *restrict bytes,
                                const size_t size_mod32) {
  const size_t size_mod4 = size_mod32 & 3;
  const uint8_t *remainder = bytes + (size_mod32 & ~3);
  uint8_t packet[32] = {0};
  for (int i = 0; i < 4; ++i) {
    state->v0[i] += ((uint64_t)size_mod32 << 32) + size_mod32;
  }
  Rotate32By(size_mod32, state->v1);
  for (int i = 0; i < remainder - bytes; i++) {
    packet[i] = bytes[i];
  }
  if (size_mod32 & 16) {
    for (int i = 0; i < 4; i++) {
      packet[28 + i] = remainder[i + size_mod4 - 4];
    }
  } else {
    if (size_mod4) {
      packet[16 + 0] = remainder[0];
      packet[16 + 1] = remainder[size_mod4 >> 1];
      packet[16 + 2] = remainder[size_mod4 - 1];
    }
  }
  HighwayHashUpdatePacket(state, packet);
}

static void Permute(const uint64_t *restrict v, uint64_t *restrict permuted) {
  permuted[0] = (v[2] >> 32) | (v[2] << 32);
  permuted[1] = (v[3] >> 32) | (v[3] << 32);
  permuted[2] = (v[0] >> 32) | (v[0] << 32);
  permuted[3] = (v[1] >> 32) | (v[1] << 32);
}

void PermuteAndUpdate(HighwayHashState *restrict state) {
  uint64_t permuted[4];
  Permute(state->v0, permuted);
  Update(state, permuted);
}

void ModularReduction(uint64_t a3_unmasked, uint64_t a2, uint64_t a1,
                      uint64_t a0, uint64_t *restrict m1,
                      uint64_t *restrict m0) {
  uint64_t a3 = a3_unmasked & 0x3FFFFFFFFFFFFFFF;
  *m1 = a1 ^ ((a3 << 1) | (a2 >> 63)) ^ ((a3 << 2) | (a2 >> 62));
  *m0 = a0 ^ (a2 << 1) ^ (a2 << 2);
}

uint64_t HighwayHashFinalize64(HighwayHashState *restrict state) {
  for (int i = 0; i < 4; i++) {
    PermuteAndUpdate(state);
  }
  return state->v0[0] + state->v1[0] + state->mul0[0] + state->mul1[0];
}

void HighwayHashFinalize128(HighwayHashState *restrict state,
                            uint64_t *restrict hash) {
  for (int i = 0; i < 6; i++) {
    PermuteAndUpdate(state);
  }
  hash[0] = state->v0[0] + state->mul0[0] + state->v1[2] + state->mul1[2];
  hash[1] = state->v0[1] + state->mul0[1] + state->v1[3] + state->mul1[3];
}

void HighwayHashFinalize256(HighwayHashState *restrict state,
                            uint64_t *restrict hash) {
  /* We anticipate that 256-bit hashing will be mostly used with long messages
     because storing and using the 256-bit hash (in contrast to 128-bit)
     carries a larger additional constant cost by itself. Doing extra rounds
     here hardly increases the per-byte cost of long messages. */
  for (int i = 0; i < 10; i++) {
    PermuteAndUpdate(state);
  }
  ModularReduction(state->v1[1] + state->mul1[1], state->v1[0] + state->mul1[0],
                   state->v0[1] + state->mul0[1], state->v0[0] + state->mul0[0],
                   &hash[1], &hash[0]);
  ModularReduction(state->v1[3] + state->mul1[3], state->v1[2] + state->mul1[2],
                   state->v0[3] + state->mul0[3], state->v0[2] + state->mul0[2],
                   &hash[3], &hash[2]);
}

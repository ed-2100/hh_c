#define HIGHWAYHASH_AVX2
#include "hh_c/highwayhash.h"

#include <emmintrin.h>
#include <immintrin.h>
#include <smmintrin.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*////////////////////////////////////////////////////////////////////////////*/
/* Internal implementation                                                    */
/*////////////////////////////////////////////////////////////////////////////*/

// Verified.
static inline void InternalHighwayHashReset(HighwayHashState *restrict state,
                                            const __m256i *key) {
  alignas(alignof(__m256i))
      const uint64_t init_mul0[] = {0xdbe6d5d5fe4cce2f, 0xa4093822299f31d0,
                                    0x13198a2e03707344, 0x243f6a8885a308d3};
  alignas(alignof(__m256i))
      const uint64_t init_mul1[] = {0x3bd39e10cb0ef593, 0xc0acf169b5f18a8c,
                                    0xbe5466cf34e90c6c, 0x452821e638d01377};
  state->mul0 = _mm256_load_si256((const __m256i *)init_mul0);
  state->mul1 = _mm256_load_si256((const __m256i *)init_mul1);
  state->v0 = _mm256_xor_si256(state->mul0, *key);
  state->v1 = _mm256_xor_si256(state->mul1,
                               _mm256_or_si256(_mm256_srli_epi64(*key, 32),
                                               _mm256_slli_epi64(*key, 32)));
}

// TODO: Verify that this matches the portable implementation.
static inline void InternalZipperMergeAndAdd(__m256i *restrict va,
                                             const __m256i *restrict vb) {
  const long long hi = 0x070806090D0A040B;
  const long long lo = 0x000F010E05020C03;
  *va = _mm256_add_epi64(
      *va, _mm256_shuffle_epi8(*vb, _mm256_set_epi64x(hi, lo, hi, lo)));
}

static void InternalUpdate(HighwayHashState *restrict state,
                           const __m256i *restrict lanes) {
  // state->v1 += state->mul0 + lanes
  state->v1 = _mm256_add_epi64(state->mul0, *lanes);

  // state->mul0 ^= (state->v1 & 0xffffffff) * (state->v0 >> 32)
  state->mul0 = _mm256_xor_si256(
      state->mul0,
      _mm256_mul_epi32(
          _mm256_and_si256(state->v1, _mm256_set1_epi64x(0xffffffff)),
          _mm256_srli_epi64(state->v0, 32)));

  state->v0 = _mm256_add_epi64(state->v0, state->mul1);

  // state->mul1 ^= (state->v0 & 0xffffffff) * (state->v1 >> 32)
  state->mul0 = _mm256_xor_si256(
      state->mul0,
      _mm256_mul_epi32(
          _mm256_and_si256(state->v0, _mm256_set1_epi64x(0xffffffff)),
          _mm256_srli_epi64(state->v1, 32)));

  InternalZipperMergeAndAdd(&state->v0, &state->v1);
  InternalZipperMergeAndAdd(&state->v1, &state->v0);
}

static void InternalHighwayHashUpdatePacket(HighwayHashState *restrict state,
                                            const __m256i *restrict packet) {
  const long long hi = 0x08090a0b0c0d0e0f;
  const long long lo = 0x0001020304050607;

  __m256i temp =
      _mm256_shuffle_epi8(*packet, _mm256_set_epi64x(hi, lo, hi, lo));
  InternalUpdate(state, &temp);
}

static inline __m256i InternalRotate32By(const __m256i *restrict lanes,
                                         const __m256i *restrict count) {
  return _mm256_or_si256(_mm256_sllv_epi32(*lanes, *count),
                         _mm256_srlv_epi32(*lanes, 32 - *count));
}

static inline void
InternalHighwayHashUpdateRemainder(HighwayHashState *restrict state,
                                   const __m256i *bytes, const int size_mod32) {
  const size_t size_mod4 = size_mod32 & 3;
  const uint8_t *remainder = (const uint8_t *)bytes + (size_mod32 & ~3);
  const __m256i size_mod32_256 = _mm256_set1_epi32(size_mod32);

  state->v0 = _mm256_add_epi64(state->v0, size_mod32_256);

  InternalRotate32By(&state->v1, &size_mod32_256);

  alignas(alignof(__m256i)) uint8_t packet[32];
  for (int i = 0; i < remainder - (const uint8_t *)bytes; i++) {
    packet[i] = ((const uint8_t *)bytes)[i];
  }

  // TODO: Vectorize this.
  if (size_mod32 & 16) { // size_mod32 >= 16
    for (int i = 0; i < 4; i++) {
      packet[28 + i] = remainder[i + size_mod4 - 4];
    }
  } else if (size_mod4) {
    packet[16 + 0] = remainder[0];
    packet[16 + 1] = remainder[size_mod4 >> 1];
    packet[16 + 2] = remainder[size_mod4 - 1];
  }

  InternalHighwayHashUpdatePacket(state, (__m256i *)packet);
}

static inline __m256i InternalPermute(const __m256i v) {
  return _mm256_permutevar8x32_epi32(v,
                                     _mm256_set_epi32(5, 4, 7, 6, 1, 0, 3, 2));
}

static void InternalPermuteAndUpdate(HighwayHashState *restrict state) {
  __m256i temp = InternalPermute(state->v0);
  InternalUpdate(state, &temp);
}

// Verified.
static inline uint64_t InternalHighwayHashFinalize64(
    HighwayHashState *restrict state) {
  for (int i = 0; i < 4; i++) {
    InternalPermuteAndUpdate(state);
  }

  return _mm256_extract_epi64(
      _mm256_add_epi64(
          _mm256_add_epi64(_mm256_add_epi64(state->v0, state->v1), state->mul0),
          state->mul1),
      0);
}

static inline __m128i
InternalHighwayHashFinalize128(HighwayHashState *restrict state) {
  for (int i = 0; i < 6; i++) {
    InternalPermuteAndUpdate(state);
  }
  const __m256i sum0 = _mm256_add_epi64(state->v0, state->mul0);
  __m256i sum1 = _mm256_add_epi64(state->v1, state->mul1);
  sum1 = _mm256_permute2f128_si256(sum1, sum1, 0x01);

  return _mm256_castsi256_si128(_mm256_add_epi64(sum0, sum1));
}

static inline __m256i ModularReduction(const __m256i b32a32, __m256i b10a10) {
  const __m256i ones = _mm256_set1_epi64x(-1);
  const __m256i zero = _mm256_xor_si256(ones, ones);

  const __m256i shifted1_unmasked = _mm256_add_epi64(b32a32, b32a32);

  b10a10 = _mm256_xor_si256(
      b10a10, _mm256_add_epi64(shifted1_unmasked, shifted1_unmasked));
  b10a10 = _mm256_xor_si256(
      b10a10, _mm256_unpacklo_epi64(zero, _mm256_srli_epi64(b32a32, 62)));
  b10a10 = _mm256_xor_si256(
      b10a10,
      _mm256_xor_si256(
          _mm256_and_si256(_mm256_slli_epi64(_mm256_slli_si256(ones, 8), 63),
                           shifted1_unmasked),
          ones));
  b10a10 = _mm256_xor_si256(
      b10a10, _mm256_unpacklo_epi64(zero, _mm256_srli_epi64(b32a32, 63)));

  return b10a10;
}

static inline __m256i
InternalHighwayHashFinalize256(HighwayHashState *restrict state) {
  for (int i = 0; i < 10; i++) {
    InternalPermuteAndUpdate(state);
  }

  const __m256i sum0 = _mm256_add_epi64(state->v0, state->mul0);
  const __m256i sum1 = _mm256_add_epi64(state->v1, state->mul1);

  return ModularReduction(sum1, sum0);
}

/*////////////////////////////////////////////////////////////////////////////*/
/* Low-level API, use for implementing streams etc...                         */
/*////////////////////////////////////////////////////////////////////////////*/

/* Initializes state with given key */
void HighwayHashReset(HighwayHashState *restrict state,
                      const uint64_t *restrict key) {
  __m256i temp = _mm256_loadu_si256((const __m256i_u *restrict)key);
  InternalHighwayHashReset(state, &temp);
}

/* Takes a packet of 32 bytes */
void HighwayHashUpdatePacket(HighwayHashState *restrict state,
                             const uint8_t *restrict packet) {
  __m256i temp = _mm256_loadu_si256((const __m256i *restrict)packet);
  InternalHighwayHashUpdatePacket(state, &temp);
}

/* Adds the final 1..31 bytes, do not use if 0 remain */
void HighwayHashUpdateRemainder(HighwayHashState *restrict state,
                                const uint8_t *restrict bytes,
                                size_t size_mod32) {
  __m256i temp = _mm256_loadu_si256((const __m256i *restrict)bytes);
  InternalHighwayHashUpdateRemainder(state, &temp, (int)size_mod32);
}

/* Compute final 64-bit hash value. Makes state invalid. */
uint64_t HighwayHashFinalize64(HighwayHashState *restrict state) {
  return InternalHighwayHashFinalize64(state);
}

/* Compute final 128-bit hash value. Makes state invalid. */
void HighwayHashFinalize128(HighwayHashState *restrict state,
                            uint64_t *restrict hash) {
  _mm_storeu_si128((__m128i_u *)hash, InternalHighwayHashFinalize128(state));
}

/* Compute final 256-bit hash value. Makes state invalid. */
void HighwayHashFinalize256(HighwayHashState *restrict state,
                            uint64_t *restrict hash) {
  _mm256_storeu_si256((__m256i_u *)hash, InternalHighwayHashFinalize256(state));
}

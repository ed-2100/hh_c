#ifndef C_HIGHWAYHASH_H_
#define C_HIGHWAYHASH_H_

#include <stdalign.h>
#include <stdint.h>
#include <string.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif


#ifdef HIGHWAYHASH_AVX2
#include <immintrin.h>
typedef struct {
  __m256i v0;
  __m256i v1;
  __m256i mul0;
  __m256i mul1;
} HighwayHashState;

typedef struct {
  HighwayHashState state;
  alignas(alignof(__m256i)) uint8_t packet[32];
  size_t num;
} HighwayHashCat;
#else
#ifndef HIGHWAYHASH_PORTABLE
#define HIGHWAYHASH_PORTABLE
#endif
typedef struct {
  uint64_t v0[4];
  uint64_t v1[4];
  uint64_t mul0[4];
  uint64_t mul1[4];
} HighwayHashState;

typedef struct {
  HighwayHashState state;
  uint8_t packet[32];
  size_t num;
} HighwayHashCat;
#endif

/*////////////////////////////////////////////////////////////////////////////*/
/* Low-level API, use for implementing streams etc...                         */
/*////////////////////////////////////////////////////////////////////////////*/

/* Initializes state with given key */
void HighwayHashReset(HighwayHashState *state, const uint64_t *key);

/* Takes a packet of 32 bytes */
void HighwayHashUpdatePacket(HighwayHashState *state, const uint8_t *packet);

/* Adds the final 1..31 bytes, do not use if 0 remain */
void HighwayHashUpdateRemainder(HighwayHashState *state, const uint8_t *bytes,
                                size_t size_mod32);

/* Compute final hash value. Makes state invalid. */
uint64_t HighwayHashFinalize64(HighwayHashState *state);
void HighwayHashFinalize128(HighwayHashState *state, uint64_t *hash);
void HighwayHashFinalize256(HighwayHashState *state, uint64_t *hash);

/*////////////////////////////////////////////////////////////////////////////*/
/* Non-cat API: single call on full data                                      */
/*////////////////////////////////////////////////////////////////////////////*/

uint64_t HighwayHash64(const uint8_t *data, size_t size, const uint64_t *key);

void HighwayHash128(const uint8_t *data, size_t size, const uint64_t *key,
                    uint64_t *hash);

void HighwayHash256(const uint8_t *data, size_t size, const uint64_t *key,
                    uint64_t *hash);

/*////////////////////////////////////////////////////////////////////////////*/
/* Cat API: allows appending with multiple calls                              */
/*////////////////////////////////////////////////////////////////////////////*/

/* Allocates new state for a new streaming hash computation */
void HighwayHashCatStart(HighwayHashCat *state, const uint64_t *key);

void HighwayHashCatAppend(HighwayHashCat *state, const uint8_t *bytes,
                          size_t num);

/* Computes final hash value */
uint64_t HighwayHashCatFinish64(const HighwayHashCat *state);
void HighwayHashCatFinish128(const HighwayHashCat *state, uint64_t *hash);
void HighwayHashCatFinish256(const HighwayHashCat *state, uint64_t *hash);

/*
Usage examples:

#include <inttypes.h>
#include <stdio.h>

void Example64() {
  uint64_t key[4] = {1, 2, 3, 4};
  const char* text = "Hello world!";
  size_t size = strlen(text);
  uint64_t hash = HighwayHash64((const uint8_t*)text, size, key);
  printf("%016"PRIx64"\n", hash);
}

void Example64Cat() {
  uint64_t key[4] = {1, 2, 3, 4};
  HighwayHashCat state;
  uint64_t hash;

  HighwayHashCatStart(key, &state);

  HighwayHashCatAppend((const uint8_t*)"Hello", 5, &state);
  HighwayHashCatAppend((const uint8_t*)" world!", 7, &state);

  hash = HighwayHashCatFinish64(&state);
  printf("%016"PRIx64"\n", hash);
}
*/

#if defined(__cplusplus) || defined(c_plusplus)
} /* extern "C" */
#endif

#endif // C_HIGHWAYHASH_H_

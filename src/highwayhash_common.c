#include "hh_c/highwayhash_internal.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/*////////////////////////////////////////////////////////////////////////////*/
/* Non-cat API: single call on full data                                      */
/*////////////////////////////////////////////////////////////////////////////*/

void ProcessAll(HighwayHashState *restrict state, const uint8_t *restrict data,
                size_t size, const uint64_t *restrict key) {
  HighwayHashReset(state, key);

  size_t i = 0;
  while (i + 32 <= size) {
    HighwayHashUpdatePacket(state, data + i);

    i += 32;
  }
  if ((size & 31) != 0) {
    HighwayHashUpdateRemainder(state, data + i, size & 31);
  }
}

uint64_t HighwayHash64(const uint8_t *restrict data, size_t size,
                       const uint64_t *restrict key) {
  HighwayHashState state;
  ProcessAll(&state, data, size, key);
  return HighwayHashFinalize64(&state);
}

void HighwayHash128(const uint8_t *restrict data, size_t size,
                    const uint64_t *restrict key, uint64_t *restrict hash) {
  HighwayHashState state;
  ProcessAll(&state, data, size, key);
  HighwayHashFinalize128(&state, hash);
}

void HighwayHash256(const uint8_t *data, size_t size,
                    const uint64_t *restrict key, uint64_t *restrict hash) {
  HighwayHashState state;
  ProcessAll(&state, data, size, key);
  HighwayHashFinalize256(&state, hash);
}

/*////////////////////////////////////////////////////////////////////////////*/
/* Cat API: allows appending with multiple calls                              */
/*////////////////////////////////////////////////////////////////////////////*/

void HighwayHashCatStart(HighwayHashCat *restrict state,
                         const uint64_t *restrict key) {
  HighwayHashReset(&state->state, key);
  state->num = 0;
}

void HighwayHashCatAppend(HighwayHashCat *restrict state,
                          const uint8_t *restrict bytes, size_t num) {
  if (state->num != 0) {
    size_t num_add = num > (32u - state->num) ? (32u - state->num) : num;
    for (size_t i = 0; i < num_add; i++) {
      state->packet[state->num + i] = bytes[i];
    }
    state->num += num_add;
    num -= num_add;
    bytes += num_add;
    if (state->num == 32) {
      HighwayHashUpdatePacket(&state->state, state->packet);
      state->num = 0;
    }
  }
  while (num >= 32) {
    HighwayHashUpdatePacket(&state->state, bytes);
    num -= 32;
    bytes += 32;
  }
  for (size_t i = 0; i < num; i++) {
    state->packet[state->num] = bytes[i];
    state->num++;
  }
}

uint64_t HighwayHashCatFinish64(const HighwayHashCat *state) {
  HighwayHashState copy = state->state;
  if (state->num) {
    HighwayHashUpdateRemainder(&copy, state->packet, state->num);
  }
  return HighwayHashFinalize64(&copy);
}

void HighwayHashCatFinish128(const HighwayHashCat *state,
                             uint64_t *restrict hash) {
  HighwayHashState copy = state->state;
  if (state->num) {
    HighwayHashUpdateRemainder(&copy, state->packet, state->num);
  }
  HighwayHashFinalize128(&copy, hash);
}

void HighwayHashCatFinish256(const HighwayHashCat *state,
                             uint64_t *restrict hash) {
  HighwayHashState copy = state->state;
  if (state->num) {
    HighwayHashUpdateRemainder(&copy, state->packet, state->num);
  }
  HighwayHashFinalize256(&copy, hash);
}

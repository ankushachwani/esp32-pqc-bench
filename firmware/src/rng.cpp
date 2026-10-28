#include <Arduino.h>
#include <esp_system.h>
#include "bench.h"
extern "C" {
#include "randombytes.h"
}

// Default source is esp_fill_random (hardware RNG register). With the radio off this is not a certified
// entropy source, which does not matter for timing. SEED <n> in the host protocol switches to a
// xorshift32 stream so a run can be repeated exactly.
static uint32_t det_state = 0;

void rng_seed_det(uint32_t seed) { det_state = seed; }
const char *rng_mode() { return det_state ? "xorshift32-seeded" : "esp_fill_random"; }

void rng_bytes(uint8_t *p, size_t n) {
    if (!det_state) { esp_fill_random(p, n); return; }
    for (size_t i = 0; i < n; i++) {
        det_state ^= det_state << 13; det_state ^= det_state >> 17; det_state ^= det_state << 5;
        p[i] = det_state >> 11;
    }
}

int rng_cb(void *, unsigned char *p, size_t n) { rng_bytes(p, n); return 0; }

// PQClean's hook (randombytes.h renames it to PQCLEAN_randombytes)
extern "C" int randombytes(uint8_t *out, size_t n) { rng_bytes(out, n); return 0; }

// Counts live heap bytes through the allocator entry points (see --wrap flags in platformio.ini).
// Sizes are what the heap reports for the block, i.e. rounded up, without the block header.
#include <stddef.h>
#include <stdint.h>
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static volatile long cur = 0, peak = 0, zero = 0;
static void *only_task = NULL;      // other tasks (serial driver) also allocate, they would pollute the count

void memtrack_only_task(void *t) { only_task = t; }

void memtrack_reset(void) { zero = cur; peak = cur; }
size_t memtrack_peak(void) { return (size_t)(peak - zero); }

static inline void add(long n) {
    if (only_task && xTaskGetCurrentTaskHandle() != only_task) return;
    cur += n; if (cur > peak) peak = cur; }
static inline long sz(void *p) { return p ? (long)heap_caps_get_allocated_size(p) : 0; }

void *__real_malloc(size_t);  void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);  void __real_free(void *);
void *__real_heap_caps_malloc(size_t, uint32_t);  void *__real_heap_caps_calloc(size_t, size_t, uint32_t);
void *__real_heap_caps_realloc(void *, size_t, uint32_t);  void __real_heap_caps_free(void *);

void *__wrap_malloc(size_t n) { void *p = __real_malloc(n); add(sz(p)); return p; }
void *__wrap_calloc(size_t a, size_t b) { void *p = __real_calloc(a, b); add(sz(p)); return p; }
void *__wrap_heap_caps_malloc(size_t n, uint32_t c) { void *p = __real_heap_caps_malloc(n, c); add(sz(p)); return p; }
void *__wrap_heap_caps_calloc(size_t a, size_t b, uint32_t c) { void *p = __real_heap_caps_calloc(a, b, c); add(sz(p)); return p; }

void *__wrap_realloc(void *o, size_t n) {
    long before = sz(o); void *p = __real_realloc(o, n);
    if (p) add(sz(p) - before);
    return p;
}
void *__wrap_heap_caps_realloc(void *o, size_t n, uint32_t c) {
    long before = sz(o); void *p = __real_heap_caps_realloc(o, n, c);
    if (p) add(sz(p) - before);
    return p;
}
void __wrap_free(void *p) { add(-sz(p)); __real_free(p); }
void __wrap_heap_caps_free(void *p) { add(-sz(p)); __real_heap_caps_free(p); }

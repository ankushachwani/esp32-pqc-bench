// Benchmark firmware: one serial command per measurement, see host/board.py and host/run_bench.py.
// Commands (one line each, answers end with END):
//   INFO | LIST | SEED <n> | BENCH <alg> <op> <min_iter> <max_iter> <budget_ms> | CHECK <alg> <trials>
//   LOAD <alg> <pklen> <siglen>, followed by pk and signature as raw bytes: a signature made off-board, for
//   algorithms whose signing does not fit in RAM. Verify and CHECK then use it instead of signing.
#include <Arduino.h>
#include <string.h>
#include <esp_heap_caps.h>
#include <esp_timer.h>
#include <esp_system.h>
#include <driver/gpio.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/semphr.h>
#include "mbedtls/version.h"
#include "sodium.h"
#include "bench.h"

Buf g;
extern const Alg *pqc_algs[], *classic_algs[];
extern const int n_pqc, n_classic;
const Alg *ALGS[32];
int N_ALGS;

// Set to a GPIO number to get a pulse around every timed call, for an external power logger.
// The same windows are in the BENCH output as start_us/dur_us. No current sensor is attached to my board.
#ifndef TRIGGER_PIN
#define TRIGGER_PIN -1
#endif
static inline void window_begin() { if (TRIGGER_PIN >= 0) gpio_set_level((gpio_num_t)TRIGGER_PIN, 1); }
static inline void window_end()   { if (TRIGGER_PIN >= 0) gpio_set_level((gpio_num_t)TRIGGER_PIN, 0); }

enum Op { KEYGEN, ENCAPS, DECAPS, SIGN, VERIFY };
static const char *OPN[] = { "keygen", "encaps", "decaps", "sign", "verify" };

// ---- worker task with a big painted stack; Falcon and ML-DSA do not fit in the Arduino loop task's 8 KB
static uint8_t *stk; static size_t stk_n;
static StaticTask_t tcb;
static SemaphoreHandle_t go, done;
static void (*job)();
static const uint32_t PAINT = 0xA5A5A5A5u;
static uintptr_t paint_top;
static const size_t PAINT_GAP = 256;
static const size_t CANARY = 64;   // FreeRTOS keeps a watchpoint at the very bottom; painting over it panics

static void __attribute__((noinline)) paint() {
    volatile uint32_t here = 0;
    paint_top = ((uintptr_t)&here - PAINT_GAP) & ~3u;
    for (uint32_t *p = (uint32_t *)(stk + CANARY); (uintptr_t)p < paint_top; p++) *p = PAINT;
}
// bytes used below the caller's frame; overflow=true when the lowest 64 bytes were touched
static size_t scan(bool *overflow) {
    uint32_t *p = (uint32_t *)(stk + CANARY);
    while ((uintptr_t)p < paint_top && *p == PAINT) p++;
    *overflow = (uintptr_t)p < (uintptr_t)stk + CANARY + 64;
    return paint_top + PAINT_GAP - (uintptr_t)p;
}
static void worker(void *) {
    for (;;) { xSemaphoreTake(go, portMAX_DELAY); job(); xSemaphoreGive(done); }
}
static void run_job(void (*f)()) { job = f; xSemaphoreGive(go); xSemaphoreTake(done, portMAX_DELAY); }

// ---- request state
static const Alg *loaded_for = nullptr;   // set by LOAD; g.pk/g.sig/g.siglen hold an external vector
static const Alg *A; static int OP, MINIT, MAXIT; static uint32_t BUDGET_MS; static int TRIALS;
static const int PROBE_RUNS = 2;
static uint32_t dur[400]; static int64_t t_start[400];

static int (*opfn(const Alg *a, int op))() {
    switch (op) {
        case KEYGEN: return a->keygen; case ENCAPS: return a->encaps; case DECAPS: return a->decaps;
        case SIGN: return a->sign;     default: return a->verify;
    }
}
// Put the state in place that the operation needs (untimed).
static int prepare(const Alg *a, int op) {
    a->reset();
    if (op == VERIFY && loaded_for == a) return 0;
    loaded_for = nullptr;
    if (op == KEYGEN) return 0;
    int rc = a->keygen();
    if (!rc && op == DECAPS) rc = a->encaps();
    if (!rc && op == VERIFY) rc = a->sign();
    return rc;
}
static void print_sizes(const Alg *a) {
    Sizes s; a->sizes(&s);
    Serial.printf("SIZES pk=%u sk=%u ct=%u sig=%u\n", (unsigned)s.pk, (unsigned)s.sk, (unsigned)s.ct, (unsigned)s.sig);
}

static void job_bench() {
    int (*f)() = opfn(A, OP);
    int rc = prepare(A, OP);
    if (rc) { Serial.printf("ERR prepare rc=%d\n", rc); return; }

    // probe: stack and heap high-water marks; these runs also serve as warm-up
    bool ovf; int fails = 0;
    memtrack_reset(); paint();
    for (int i = 0; i < PROBE_RUNS; i++) fails += (f() != 0);
    size_t used = scan(&ovf), heap = memtrack_peak();
    Serial.printf("MEM stack=%u stack_total=%u overflow=%d heap=%u\n", (unsigned)used, (unsigned)stk_n, ovf, (unsigned)heap);
    print_sizes(A);

    int n = 0; double sl_sum = 0; size_t sl_max = 0;
    int64_t t0 = esp_timer_get_time();
    for (; n < MAXIT && n < 400; n++) {
        int64_t a = esp_timer_get_time();
        window_begin();
        rc = f();
        window_end();
        int64_t b = esp_timer_get_time();
        t_start[n] = a; dur[n] = (uint32_t)(b - a); fails += (rc != 0);
        if (OP == SIGN) { sl_sum += g.siglen; if (g.siglen > sl_max) sl_max = g.siglen; }
        if (n + 1 >= MINIT && (b - t0) >= (int64_t)BUDGET_MS * 1000) { n++; break; }
    }
    for (int i = 0; i < n; i++) Serial.printf("T %d %lld %u\n", i, (long long)t_start[i], (unsigned)dur[i]);
    Serial.printf("STAT n=%d fails=%d siglen_mean=%.1f siglen_max=%u\n", n, fails, n ? sl_sum / n : 0.0, (unsigned)sl_max);
}

static void job_check() {
    const Alg *a = A; Sizes s;
    int ok = 0, tamper = 0, tamper2 = 0, errs = 0;
    for (int t = 0; t < TRIALS; t++) {
        a->reset();
        bool ext = loaded_for == a;      // keep the external key, signature and message
        if (!ext) { rng_bytes(g.msg, MSG_LEN); if (a->keygen()) { errs++; continue; } }
        a->sizes(&s);
        if (a->encaps) {
            if (a->encaps()) { errs++; continue; }
            bool good = a->decaps() == 0 && !memcmp(g.ss1, g.ss2, 32);
            ok += good;
            // a modified ciphertext must not give the same secret (error or implicit rejection both count)
            memset(g.ss2, 0, 32);
            g.ct[s.ct / 2] ^= 1;
            int rc = a->decaps();
            tamper += (rc != 0 || memcmp(g.ss1, g.ss2, 32) != 0);
            g.ct[s.ct / 2] ^= 1;
        } else {
            if (!ext && a->sign()) { errs++; continue; }
            ok += a->verify() == 0;
            g.sig[g.siglen / 2] ^= 1;  tamper += a->verify() != 0;  g.sig[g.siglen / 2] ^= 1;
            g.msg[0] ^= 1;             tamper2 += a->verify() != 0; g.msg[0] ^= 1;
            ok -= a->verify() != 0;    // the restored pair has to verify again
        }
    }
    if (a->encaps) Serial.printf("CHECK trials=%d roundtrip_ok=%d tampered_ct_rejected=%d errors=%d\n", TRIALS, ok, tamper, errs);
    else Serial.printf("CHECK trials=%d valid_sig_ok=%d bad_sig_rejected=%d bad_msg_rejected=%d errors=%d\n", TRIALS, ok, tamper, tamper2, errs);
}

static void info() {
    Serial.printf("cpu_mhz=%u\n", (unsigned)getCpuFrequencyMhz());
    Serial.printf("reset_reason=%d\n", (int)esp_reset_reason());     // 1 power-on, 3 software, 4 panic, 5/6/7 watchdog
    Serial.printf("idf=%s\n", esp_get_idf_version());
    Serial.printf("mbedtls=%s\nlibsodium=%s\n", MBEDTLS_VERSION_STRING, sodium_version_string());
    Serial.printf("compiler=%s\n", __VERSION__);
    Serial.printf("free_heap=%u\nlargest_block=%u\nworker_stack=%u\n",
                  (unsigned)heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT),
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT), (unsigned)stk_n);
    Serial.printf("rng=%s\ntrigger_pin=%d\nmsg_len=%d\n", rng_mode(), TRIGGER_PIN, MSG_LEN);
}

static int opindex(const char *s) { for (int i = 0; i < 5; i++) if (!strcmp(s, OPN[i])) return i; return -1; }

static void handle(char *line) {
    char cmd[16] = "", op[16] = ""; int ai = -1, a1 = 0, a2 = 0; unsigned a3 = 0;
    sscanf(line, "%15s", cmd);
    if (!strcmp(cmd, "INFO")) info();
    else if (!strcmp(cmd, "LIST")) {
        for (int i = 0; i < N_ALGS; i++) {
            const Alg *a = ALGS[i];
            Serial.printf("ALG %d|%s|%s|%s|%d\n", i, a->name, a->kind, a->family, a->pqc);
        }
    } else if (!strcmp(cmd, "SEED")) { sscanf(line, "%*s %u", &a3); rng_seed_det(a3); Serial.printf("rng=%s\n", rng_mode()); }
    else if (!strcmp(cmd, "BENCH") && sscanf(line, "%*s %d %15s %d %d %u", &ai, op, &a1, &a2, &a3) == 5
             && ai >= 0 && ai < N_ALGS && opindex(op) >= 0) {
        A = ALGS[ai]; OP = opindex(op); MINIT = a1; MAXIT = a2; BUDGET_MS = a3;
        if (!opfn(A, OP)) { Serial.println("ERR op not supported"); return; }
        run_job(job_bench);
    } else if (!strcmp(cmd, "LOAD") && sscanf(line, "%*s %d %d %d", &ai, &a1, &a2) == 3
               && ai >= 0 && ai < N_ALGS && a1 <= MAX_PK && a2 <= MAX_SIG) {
        Serial.setTimeout(5000);
        bool ok = Serial.readBytes(g.pk, a1) == (size_t)a1 && Serial.readBytes(g.sig, a2) == (size_t)a2;
        if (!ok) { Serial.println("ERR short load"); return; }
        g.siglen = a2; loaded_for = ALGS[ai];
        for (int i = 0; i < MSG_LEN; i++) g.msg[i] = (uint8_t)(i * 7 + 1);
    } else if (!strcmp(cmd, "CHECK") && sscanf(line, "%*s %d %d", &ai, &a1) == 2 && ai >= 0 && ai < N_ALGS) {
        A = ALGS[ai]; TRIALS = a1; run_job(job_check);
    } else { Serial.println("ERR bad command"); return; }
    Serial.println("END");
}

void setup() {
    Serial.begin(115200);
    for (int i = 0; i < n_pqc; i++) ALGS[N_ALGS++] = pqc_algs[i];
    for (int i = 0; i < n_classic; i++) ALGS[N_ALGS++] = classic_algs[i];
    for (int i = 0; i < MSG_LEN; i++) g.msg[i] = (uint8_t)(i * 7 + 1);
    if (TRIGGER_PIN >= 0) { gpio_set_direction((gpio_num_t)TRIGGER_PIN, GPIO_MODE_OUTPUT); gpio_set_level((gpio_num_t)TRIGGER_PIN, 0); }

    // take almost all of the biggest contiguous internal block for the worker stack; mbedtls allocates from the other DRAM region
    size_t big = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    stk_n = (big - 4 * 1024) & ~3u;
    stk = (uint8_t *)heap_caps_malloc(stk_n, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    go = xSemaphoreCreateBinary(); done = xSemaphoreCreateBinary();
    disableCore1WDT();
    memtrack_only_task((void *)xTaskCreateStaticPinnedToCore(worker, "bench", stk_n, nullptr, 5, stk, &tcb, 1));
    Serial.println("READY pqc-bench");
}

void loop() {
    static char buf[96]; static int n = 0;
    while (Serial.available()) {
        char c = Serial.read();
        if (c == '\n' || c == '\r') { if (n) { buf[n] = 0; n = 0; handle(buf); } }
        else if (n < (int)sizeof(buf) - 1) buf[n++] = c;
    }
    delay(1);
}

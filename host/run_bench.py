"""Drive the benchmark firmware and write raw CSVs. Run on the Pi (needs pyserial), with the board lock held.

    python3 host/run_bench.py --out results/raw            # full run
    python3 host/run_bench.py --quick --out /tmp/q          # a few iterations each, to check the setup
    python3 host/run_bench.py --only ML-DSA --out /tmp/x    # name substring filter
"""
import argparse, csv, os, sys, time
sys.path.insert(0, os.path.dirname(__file__))
from board import Board, kv

VEC_DIR = os.path.join(os.path.dirname(__file__), 'vectors')


def vector(name):
    """Signature made off-board (host/gen_vector.c), used only when signing crashes on the board."""
    fn = os.path.join(VEC_DIR, name.lower() + '.bin')
    if not os.path.exists(fn): return None
    d = open(fn, 'rb').read(); pl = d[0] | d[1] << 8; sl = d[2] | d[3] << 8
    return d[4:4 + pl], d[4 + pl:4 + pl + sl]

OPS = {'kem': ['keygen', 'encaps', 'decaps'], 'sig': ['keygen', 'sign', 'verify']}

# (min iterations, check trials) for the slow ones; everything else uses the defaults below.
SLOW = {
    'RSA-2048 (OAEP)':        {'keygen': 5},
    'RSA-2048 (PKCS1v1.5)':   {'keygen': 5},
    'SPHINCS+-SHA2-128f':     {'keygen': 5, 'sign': 5},
    'SPHINCS+-SHA2-128s':     {'keygen': 3, 'sign': 3},
}
CHECK_TRIALS = {'RSA-2048 (OAEP)': 3, 'RSA-2048 (PKCS1v1.5)': 3, 'SPHINCS+-SHA2-128s': 2}


def recover(b):
    """After a crash the board prints the boot banner; wait for it to go quiet, then carry on."""
    time.sleep(2.0)
    b.s.reset_input_buffer()
    return dict(l.split('=', 1) for l in b.cmd('INFO') if '=' in l).get('reset_reason')


REASON = {'1': 'power-on', '3': 'software reset', '4': 'panic (exception)', '5': 'interrupt watchdog',
          '6': 'task watchdog', '7': 'other watchdog'}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--out', default='results/raw')
    ap.add_argument('--budget', type=float, default=10.0, help='seconds of timed calls per operation')
    ap.add_argument('--min-iter', type=int, default=10)
    ap.add_argument('--max-iter', type=int, default=300)
    ap.add_argument('--quick', action='store_true')
    ap.add_argument('--only', default='')
    ap.add_argument('--seed', type=int, default=0, help='nonzero: deterministic xorshift rng instead of esp_fill_random')
    a = ap.parse_args()
    if a.quick: a.budget, a.min_iter, a.max_iter = 0.5, 3, 5
    os.makedirs(a.out, exist_ok=True)

    b = Board()
    info = b.cmd('INFO')
    info_kv = dict(l.split('=', 1) for l in info if '=' in l)
    if a.seed: b.cmd('SEED %d' % a.seed)
    with open(os.path.join(a.out, 'board_info.txt'), 'w') as f:
        f.write('\n'.join(info) + '\n')
        f.write('budget_s=%g min_iter=%d max_iter=%d seed=%d\n' % (a.budget, a.min_iter, a.max_iter, a.seed))

    algs = []
    for ln in b.cmd('LIST'):
        i, name, kind, fam, pqc = ln[4:].split('|')
        if a.only in name: algs.append((int(i), name, kind, fam, int(pqc)))

    def writer(fn, header):
        f = open(os.path.join(a.out, fn), 'w', newline=''); w = csv.writer(f); w.writerow(header); return f, w
    lf, lat = writer('latency.csv', ['alg', 'op', 'iter', 'start_us', 'dur_us'])
    mf, mem = writer('memory.csv', ['alg', 'op', 'status', 'stack_bytes', 'stack_available', 'stack_overflow',
                                    'heap_bytes', 'n_iter', 'failed_calls', 'siglen_mean', 'siglen_max', 'note'])
    sf, siz = writer('sizes.csv', ['alg', 'kind', 'family', 'pqc', 'pk', 'sk', 'ct', 'sig_max'])
    cf, chk = writer('checks.csv', ['alg', 'trials', 'valid_ok', 'tamper_rejected', 'tamper2_rejected', 'errors', 'what'])

    for i, name, kind, fam, pqc in algs:
        print('==', name, flush=True)
        sizes_done = False; sign_crashed = False; loaded = False
        for op in OPS[kind]:
            if op == 'verify' and sign_crashed and vector(name):
                b.load(i, *vector(name)); loaded = True
            mn = SLOW.get(name, {}).get(op, a.min_iter)
            if a.quick: mn = min(mn, 3)
            t0 = time.time()
            try:
                lines = b.cmd('BENCH %d %s %d %d %d' % (i, op, mn, a.max_iter, int(a.budget * 1000)), timeout=7200)
            except RuntimeError as e:
                print('   %-7s FAILED: %s' % (op, e), flush=True)
                why = REASON.get(recover(b), '?')
                mem.writerow([name, op, 'crash', '', '', '', '', 0, '', '', '',
                              'board rebooted, reset reason: %s, worker stack %s B' % (why, info_kv.get('worker_stack'))]); mf.flush()
                if op == 'sign': sign_crashed = True
                continue
            m = [kv(l) for l in lines if l.startswith('MEM')][0]
            st = [kv(l) for l in lines if l.startswith('STAT')][0]
            sz = [kv(l) for l in lines if l.startswith('SIZES')][0]
            ts = [l.split() for l in lines if l.startswith('T ')]
            for _, it, s, d in ts: lat.writerow([name, op, it, s, d])
            mem.writerow([name, op, 'ok' if not m['overflow'] else 'stack_overflow', m['stack'], m['stack_total'], m['overflow'],
                          m['heap'], st['n'], st['fails'], st['siglen_mean'], st['siglen_max'],
                          'signature made off-board' if op == 'verify' and loaded else ''])
            if op == 'keygen' and not sizes_done:
                siz.writerow([name, kind, fam, pqc, sz['pk'], sz['sk'], sz['ct'], sz['sig']]); sizes_done = True
            for f in (lf, mf, sf): f.flush()
            durs = [int(d) for *_, d in ts]
            print('   %-7s n=%-4d mean=%.0f us  stack=%d B  heap=%d B  fails=%d  (%.0f s)' %
                  (op, len(durs), sum(durs) / len(durs), m['stack'], m['heap'], st['fails'], time.time() - t0), flush=True)
        if loaded: b.load(i, *vector(name))
        trials = 2 if a.quick else CHECK_TRIALS.get(name, 10)
        try:
            c = kv(b.cmd('CHECK %d %d' % (i, trials), timeout=3600)[0])
        except RuntimeError as e:
            print('   CHECK FAILED:', e, flush=True); recover(b); continue
        if kind == 'kem':
            chk.writerow([name, c['trials'], c['roundtrip_ok'], c['tampered_ct_rejected'], '', c['errors'],
                          'shared secrets equal; modified ciphertext gives error or different secret'])
        else:
            chk.writerow([name, c['trials'], c['valid_sig_ok'], c['bad_sig_rejected'], c['bad_msg_rejected'], c['errors'],
                          'valid sig verifies; flipped sig byte rejected; flipped message byte rejected'
                          + ('; signature made off-board' if loaded else '')])
        cf.flush()
        print('   check', c, flush=True)


if __name__ == '__main__':
    main()

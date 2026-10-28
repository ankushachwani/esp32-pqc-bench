"""Raw CSVs in results/raw -> results/summary.csv, results/summary.md, and the figures.

    python3 analysis/make_table.py            (needs pandas and matplotlib; runs on the Mac, not the Pi)

Nothing here is typed in by hand except which linker-map members belong to which classical algorithm.
"""
import os, sys
import pandas as pd
import numpy as np

ROOT = os.path.join(os.path.dirname(__file__), '..')
RAW = os.path.join(ROOT, 'results', 'raw')
OUT = os.path.join(ROOT, 'results')

lat = pd.read_csv(os.path.join(RAW, 'latency.csv'))
mem = pd.read_csv(os.path.join(RAW, 'memory.csv'))
siz = pd.read_csv(os.path.join(RAW, 'sizes.csv'))
chk = pd.read_csv(os.path.join(RAW, 'checks.csv'))
cs = pd.read_csv(os.path.join(RAW, 'code_size_members.csv'))

ORDER = ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024', 'RSA-2048 (OAEP)', 'ECDH P-256', 'X25519 (mbedtls)', 'X25519 (libsodium)',
         'ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87', 'Falcon-512', 'SPHINCS+-SHA2-128f', 'SPHINCS+-SHA2-128s',
         'RSA-2048 (PKCS1v1.5)', 'ECDSA P-256', 'Ed25519 (libsodium)']
KIND = {a: k for a, k in zip(siz.alg, siz.kind)}
PQC = {a: bool(p) for a, p in zip(siz.alg, siz.pqc)}
FAMILY = {a: f for a, f in zip(siz.alg, siz.family)}

# ---- long-form summary
g = lat.groupby(['alg', 'op'])['dur_us']
st = pd.DataFrame({'n': g.size(), 'mean_ms': g.mean() / 1e3, 'std_ms': g.std(ddof=1) / 1e3, 'min_ms': g.min() / 1e3,
                   'max_ms': g.max() / 1e3, 'median_ms': g.median() / 1e3}).reset_index()
summ = mem.merge(st, on=['alg', 'op'], how='left')
summ['kind'] = summ.alg.map(KIND); summ['pqc'] = summ.alg.map(PQC)
summ = summ[['alg', 'kind', 'pqc', 'op', 'status', 'n', 'mean_ms', 'std_ms', 'min_ms', 'max_ms', 'median_ms',
             'stack_bytes', 'heap_bytes', 'siglen_mean', 'siglen_max', 'note']]
summ['_o'] = summ.alg.map({a: i for i, a in enumerate(ORDER)})
summ = summ.sort_values(['_o']).drop(columns='_o')
summ.round(4).to_csv(os.path.join(OUT, 'summary.csv'), index=False)

# ---- code size: which linker-map members count for which algorithm
MB = lambda *names: [n + '.c.obj' for n in names]
CLASSIC = {
    'RSA-2048': ('libmbedcrypto', MB('rsa', 'rsa_internal', 'bignum', 'esp_bignum', 'oid', 'md', 'constant_time')),
    'ECDH/ECDSA P-256 + X25519 (mbedtls)': ('libmbedcrypto', MB('ecp', 'ecp_curves', 'ecdh', 'ecdsa', 'bignum', 'esp_bignum',
                                                                 'asn1parse', 'asn1write', 'hmac_drbg', 'md', 'constant_time')),
    'Ed25519 (libsodium)': ('liblibsodium', MB('ed25519_ref10', 'hash_sha512_cp', 'sign', 'crypto_sign', 'keypair', 'open',
                                               'verify', 'utils')),
    'X25519 (libsodium)': ('liblibsodium', MB('x25519_ref10', 'scalarmult_curve25519')),
}
def sz(group, members=None):
    d = cs[cs.group == group]
    if members is not None: d = d[d.member.isin(members)]
    t = d.groupby('class').bytes.sum()
    return int(t.get('code', 0)), int(t.get('rodata', 0)), int(t.get('data', 0))

code_rows = []
for a in ORDER:
    d = {'ML-KEM': 'ml-kem-%s', 'ML-DSA': 'ml-dsa-%s'}
    if a.startswith('ML-KEM') or a.startswith('ML-DSA'):
        grp = 'pqclean/' + a.lower()
    elif a == 'Falcon-512': grp = 'pqclean/falcon-512'
    elif a.startswith('SPHINCS'): grp = 'pqclean/sphincs-sha2-128%s-simple' % a[-1]
    else: continue
    c, r, dd = sz(grp)
    code_rows.append((a, c, r, dd, 'PQClean objects of this scheme only; the hash code below is shared'))
for a, (grp, mem_) in CLASSIC.items():
    c, r, dd = sz(grp, mem_)
    code_rows.append((a, c, r, dd, 'mbedtls/libsodium objects pulled in by the benchmark: ' + ', '.join(m.replace('.c.obj', '') for m in mem_)))
com = cs[cs.group == 'pqclean/common']
for m, label in (('fips202.o', 'fips202 (SHAKE, shared by ML-KEM, ML-DSA, Falcon)'), ('sha2.o', 'sha2 (shared by SPHINCS+-SHA2)')):
    t = com[com.member == m].groupby('class').bytes.sum()
    code_rows.append((label, int(t.get('code', 0)), int(t.get('rodata', 0)), int(t.get('data', 0)), 'PQClean common/'))
code = pd.DataFrame(code_rows, columns=['component', 'code_bytes', 'rodata_bytes', 'static_ram_bytes', 'note'])
code.to_csv(os.path.join(OUT, 'code_size.csv'), index=False)
CODE = {r.component: r for r in code.itertuples()}
SHAKE = [k for k in CODE if k.startswith('fips202')][0]
SHA2 = [k for k in CODE if k.startswith('sha2')][0]

# ---- markdown
def cell(a, op, kb=False):
    r = summ[(summ.alg == a) & (summ.op == op)]
    if r.empty: return 'n/a'
    r = r.iloc[0]
    if r.status != 'ok': return 'does not fit'
    f = lambda v: ('%.2f' if v < 10 else '%.1f' if v < 100 else '%.0f') % v
    mark = '&dagger;' if isinstance(r.note, str) and 'off-board' in r.note else ''
    return '%s &plusmn; %s%s' % (f(r.mean_ms), f(r.std_ms), mark)

def peak(a, col):
    r = summ[(summ.alg == a) & (summ.status == 'ok')][col]
    return r.max() if len(r) else np.nan

def total(a, ops):
    v = [summ[(summ.alg == a) & (summ.op == o)] for o in ops]
    if any(x.empty or x.iloc[0].status != 'ok' for x in v): return 'n/a'
    t = sum(x.iloc[0].mean_ms for x in v)
    return ('%.1f' if t < 100 else '%.0f') % t

def stack_cell(a):
    bad = summ[(summ.alg == a) & (summ.status != 'ok')]
    p = peak(a, 'stack_bytes')
    s = '%.1f' % (p / 1024)
    return s + (' (sign: no fit)' if len(bad) else '')

def flash(a):
    key = {'RSA-2048 (OAEP)': 'RSA-2048', 'RSA-2048 (PKCS1v1.5)': 'RSA-2048', 'ECDH P-256': 'ECDH/ECDSA P-256 + X25519 (mbedtls)',
           'ECDSA P-256': 'ECDH/ECDSA P-256 + X25519 (mbedtls)', 'X25519 (mbedtls)': 'ECDH/ECDSA P-256 + X25519 (mbedtls)'}.get(a, a)
    r = CODE.get(key)
    if r is None: return ''
    b = r.code_bytes + r.rodata_bytes
    # PQC rows include the shared hash code they need
    if a.startswith(('ML-', 'Falcon')): b += CODE[SHAKE].code_bytes + CODE[SHAKE].rodata_bytes
    if a.startswith('SPHINCS'): b += CODE[SHA2].code_bytes + CODE[SHA2].rodata_bytes
    return '%.1f' % (b / 1024)

def checkcell(a):
    r = chk[chk.alg == a]
    if r.empty: return 'not run'
    r = r.iloc[0]
    if KIND[a] == 'kem': return '%d/%d ok, %d/%d tampered rejected' % (r.valid_ok, r.trials, r.tamper_rejected, r.trials)
    return '%d/%d ok, %d/%d bad sig, %d/%d bad msg' % (r.valid_ok, r.trials, r.tamper_rejected, r.trials, r.tamper2_rejected, r.trials)

sz_ = siz.set_index('alg')
L = []
L.append('# Results\n')
L.append('Generated by analysis/make_table.py from results/raw. Latency is mean &plusmn; standard deviation in ms over the timed iterations (n is in summary.csv). ')
L.append('Stack is the peak measured by stack painting, in KiB, max over the three operations. Heap is the peak of live allocations above the starting point, max over operations. ')
L.append('Flash is code plus read-only data of the objects that belong to the algorithm, including the PQClean hash code (SHAKE or SHA-2) it needs; the per-component split is at the bottom. Sizes are in bytes.\n')
L.append('## Key establishment\n')
L.append('| Algorithm | keygen ms | encaps ms | decaps ms | sum ms | stack KiB | heap B | pk | ct | sk | flash KiB | on-board check |')
L.append('|---|---|---|---|---|---|---|---|---|---|---|---|')
for a in ORDER:
    if KIND.get(a) != 'kem': continue
    s = sz_.loc[a]
    L.append('| %s | %s | %s | %s | %s | %s | %d | %d | %d | %d | %s | %s |' % (
        a, cell(a, 'keygen'), cell(a, 'encaps'), cell(a, 'decaps'), total(a, ['keygen', 'encaps', 'decaps']),
        stack_cell(a), peak(a, 'heap_bytes'), s.pk, s.ct, s.sk, flash(a), checkcell(a)))
L.append('\nFor ECDH and X25519, encaps is "generate an ephemeral key and derive the secret" and decaps is the derive alone, so the sum is one full exchange seen from both ends. RSA-2048 is RSAES-OAEP with SHA-256 on a 32-byte secret.\n')
L.append('## Signatures\n')
L.append('| Algorithm | keygen ms | sign ms | verify ms | sign+verify ms | stack KiB | heap B | pk | sig (max) | sk | flash KiB | on-board check |')
L.append('|---|---|---|---|---|---|---|---|---|---|---|---|')
for a in ORDER:
    if KIND.get(a) != 'sig': continue
    s = sz_.loc[a]
    L.append('| %s | %s | %s | %s | %s | %s | %d | %d | %d | %d | %s | %s |' % (
        a, cell(a, 'keygen'), cell(a, 'sign'), cell(a, 'verify'), total(a, ['sign', 'verify']),
        stack_cell(a), peak(a, 'heap_bytes'), s.pk, s.sig_max, s.sk, flash(a), checkcell(a)))
nf = summ[summ.status != 'ok']
L.append('\n&dagger; the signature was produced off-board (host/gen_vector.c) because signing does not fit; verify time and stack are measured on the board.')
for r in nf.itertuples():
    L.append('\n"does not fit": %s %s. %s.' % (r.alg, r.op, r.note))
L.append('\n## Code size per component\n')
L.append('| Component | code B | rodata B | static RAM B | note |')
L.append('|---|---|---|---|---|')
for r in code.itertuples():
    L.append('| %s | %d | %d | %d | %s |' % (r.component, r.code_bytes, r.rodata_bytes, r.static_ram_bytes, r.note))
open(os.path.join(OUT, 'summary.md'), 'w').write('\n'.join(L) + '\n')

# ---- figures
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
COL = {'lattice': '#2b6cb0', 'hash': '#2f855a', 'rsa': '#c05621', 'ecc': '#b7791f'}
LAB = {'lattice': 'PQC, lattice', 'hash': 'PQC, hash-based', 'rsa': 'classical, RSA', 'ecc': 'classical, elliptic curve'}
plt.rcParams.update({'font.size': 9, 'axes.spines.top': False, 'axes.spines.right': False, 'axes.grid': True,
                     'grid.alpha': 0.3, 'axes.axisbelow': True})

def legend(ax):
    from matplotlib.patches import Patch
    ax.legend(handles=[Patch(color=COL[k], label=LAB[k]) for k in COL], loc='lower right', frameon=False, fontsize=8)

def latency_panel(ax, kind, ops):
    algs = [a for a in ORDER if KIND.get(a) == kind]
    h = 0.8 / len(ops)
    for j, op in enumerate(ops):
        for i, a in enumerate(algs):
            r = summ[(summ.alg == a) & (summ.op == op)]
            y = i + (j - (len(ops) - 1) / 2) * h
            if r.empty or r.iloc[0].status != 'ok':
                ax.text(0.01, y, 'sign does not fit in RAM', va='center', fontsize=7, color='#555', transform=ax.get_yaxis_transform()); continue
            r = r.iloc[0]
            ax.barh(y, r.mean_ms, height=h * 0.9, color=COL[FAMILY[a]], alpha=0.35 + 0.3 * j, linewidth=0)
            ax.plot([r.min_ms, r.max_ms], [y, y], color='#222', lw=0.8)
    ax.set_yticks(range(len(algs))); ax.set_yticklabels(algs); ax.invert_yaxis()
    ax.set_xscale('log'); ax.set_xlabel('ms per operation (bar = mean, line = min to max), log scale')
    ax.set_title('Key establishment: keygen / encaps / decaps (dark to light = later ops)' if kind == 'kem'
                 else 'Signatures: keygen / sign / verify (dark to light = later ops)', fontsize=9, loc='left')
    legend(ax)

fig, axs = plt.subplots(2, 1, figsize=(8, 9.5), gridspec_kw={'height_ratios': [7, 9]})
latency_panel(axs[0], 'kem', ['keygen', 'encaps', 'decaps'])
latency_panel(axs[1], 'sig', ['keygen', 'sign', 'verify'])
fig.tight_layout(); fig.savefig(os.path.join(OUT, 'latency.png'), dpi=160); plt.close(fig)

# memory: peak stack, flash, key material on the wire
algs = ORDER
fig, axs = plt.subplots(1, 3, figsize=(13, 6.5), sharey=True)
for ax, title in zip(axs, ['peak stack, KiB', 'flash (code + rodata), KiB', 'bytes on the wire (pk + ct, or pk + sig)']):
    ax.set_title(title, fontsize=9, loc='left'); ax.set_xscale('log')
for i, a in enumerate(algs):
    c = COL[FAMILY[a]]
    p = peak(a, 'stack_bytes') / 1024
    axs[0].barh(i, p, color=c, height=0.7)
    if len(summ[(summ.alg == a) & (summ.status != 'ok')]): axs[0].text(p * 1.1, i, 'sign did not fit', va='center', fontsize=7)
    f = flash(a)
    if f: axs[1].barh(i, float(f), color=c, height=0.7)
    s = sz_.loc[a]
    axs[2].barh(i, s.pk + (s.ct if KIND[a] == 'kem' else s.sig_max), color=c, height=0.7)
axs[1].set_xlim(3, 200); axs[0].set_xlim(1, 200)
axs[0].set_yticks(range(len(algs))); axs[0].set_yticklabels(algs); axs[0].invert_yaxis()
legend(axs[2])
fig.tight_layout(); fig.savefig(os.path.join(OUT, 'memory.png'), dpi=160); plt.close(fig)
print('wrote summary.csv, summary.md, code_size.csv, latency.png, memory.png')

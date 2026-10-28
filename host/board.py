"""Serial driver for the benchmark firmware. Runs on the machine the ESP32 is plugged into (the Pi)."""
import time
import serial

PORT = '/dev/ttyUSB0'
BANNER = 'READY pqc-bench'


class Board:
    def __init__(self, port=PORT, baud=115200, boot_timeout=15):
        self.s = serial.Serial(port, baud, timeout=1)
        self.reset(boot_timeout)

    def reset(self, timeout=15):
        s = self.s
        s.dtr = False; s.rts = True; time.sleep(0.1); s.rts = False
        t0 = time.time()
        while time.time() - t0 < timeout:
            if s.readline().decode(errors='replace').strip().startswith(BANNER):
                quiet = time.time()      # opening the port can reset the board twice, wait for silence
                while time.time() - quiet < 1.5:
                    if s.readline(): quiet = time.time()
                s.reset_input_buffer()
                return
        raise RuntimeError('no %s banner' % BANNER)

    def load(self, idx, pk, sig, timeout=30):
        """Send an externally made public key and signature (see LOAD in the firmware)."""
        self.s.write(('LOAD %d %d %d\n' % (idx, len(pk), len(sig))).encode() + pk + sig); self.s.flush()
        t0 = time.time()
        while time.time() - t0 < timeout:
            ln = self.s.readline().decode(errors='replace').strip()
            if ln == 'END': return
            if ln.startswith('ERR'): raise RuntimeError(ln)
        raise TimeoutError('no END after LOAD')

    def cmd(self, line, timeout=120):
        """Send a command, return the lines before END. A reboot (banner) or ERR raises."""
        self.s.write((line + '\n').encode()); self.s.flush()
        out = []; t0 = time.time()
        while time.time() - t0 < timeout:
            ln = self.s.readline().decode(errors='replace').strip()
            if not ln: continue
            if ln == 'END': return out
            if ln.startswith(BANNER): raise RuntimeError('board rebooted during: ' + line)
            if ln.startswith('ERR'): raise RuntimeError(ln + ' (' + line + ')')
            out.append(ln)
        raise TimeoutError('no END after %ds for: %s' % (timeout, line))


def kv(line):
    """'MEM stack=100 heap=0' -> {'stack': 100, 'heap': 0}"""
    d = {}
    for tok in line.split():
        if '=' in tok:
            k, v = tok.split('=', 1)
            try: d[k] = float(v) if '.' in v else int(v)
            except ValueError: d[k] = v
    return d

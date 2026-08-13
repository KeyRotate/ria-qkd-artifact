#!/usr/bin/env python3
"""Self-contained offline PPK2-0.9.2 decode of raw Power Profiler Kit II .bin captures.

Reproduces the archived analysis path from the raw capture bytes alone (no PPK2
serial device, no network). It implements the exact ppk2-api==0.9.2 default
('Calibrated: 0') conversion pipeline:

  RANGE = raw >> 14 & 0x7   (clamped to 4)
  ADC   = (raw & 0x3FFF) * 4
  r     = (ADC - O[r]) * (adc_mult / R[r])          with adc_mult = 1.8 / 163840
  i     = UG[r] * ( r * (GS[r] * r + GI[r]) + S[r]*(VDD/1000) + I[r] )
  uA    = i * 1e6           (after the library's rolling-average / spike filter)

with the archived constants (identical to the ppk2-api 0.9.2 defaults):

  R  = [1031.64, 101.65, 10.15, 0.94, 0.043]
  GS = GI = UG = [1,1,1,1,1];  O = S = I = [0,0,0,0,0]

VDD = 3300 mV, fs = 100 kHz, V = 3.3 V. Digital channel 0 (DIO0, PA5 marker on
the STM32F407G-DISC1) delimits the measured windows.

Usage:
    python3 ppk2_offline_decode.py capture1.bin capture2.bin ... [--csv out.csv]
    python3 ppk2_offline_decode.py m4bench/ppk2_cap_log.bin --benchmark --csv sign_windows.csv

The pulse table (start time, duration, average current, peak current, energy)
is written to stdout; with --csv, one machine-readable row per pulse is
appended to the given file.
"""

import getopt
import sys


def _generate_mask(bits, pos):
    """14-bit ADC mask, 3-bit range mask, 8-bit logic mask (ppk2-api 0.9.2)."""
    mask = ((2 ** bits - 1) << pos)
    mask = mask & 0xFFFFFFFF
    if mask & 0x80000000:
        mask = -(~mask + 1)
    return {"mask": mask, "pos": pos}


MASKS = {
    "ADC": _generate_mask(14, 0),
    "RANGE": _generate_mask(3, 14),
    "LOGIC": _generate_mask(8, 24),
}

R = [1031.64, 101.65, 10.15, 0.94, 0.043]
GS = [1.0] * 5
GI = [1.0] * 5
UG = [1.0] * 5
O = [0.0] * 5
S = [0.0] * 5
I = [0.0] * 5
ADC_MULT = 1.8 / 163840
VDD_MV = 3300
FS = 100000.0
V = 3.3

SPIKE_ALPHA = 0.18
SPIKE_ALPHA5 = 0.06
SPIKE_SAMPLES = 3


def decode_samples(buf):
    """Return (uA[], range[], d0[]) replicating ppk2-api 0.9.2 get_samples()."""
    rolling_avg = None
    rolling_avg4 = None
    prev_range = None
    consecutive_range_samples = 0
    after_spike = 0

    ua = []
    rng = []
    d0 = []
    n = len(buf)
    off = 0
    first = True
    while off + 4 <= n:
        raw = int.from_bytes(buf[off:off + 4], byteorder="little", signed=False)
        off += 4
        cur_range = min((raw & MASKS["RANGE"]["mask"]) >> MASKS["RANGE"]["pos"], 4)
        adc = ((raw & MASKS["ADC"]["mask"]) >> MASKS["ADC"]["pos"]) * 4
        logic = (raw & MASKS["LOGIC"]["mask"]) >> MASKS["LOGIC"]["pos"]

        cr = cur_range
        r = (adc - O[cr]) * (ADC_MULT / R[cr])
        val = UG[cr] * (r * (GS[cr] * r + GI[cr]) + S[cr] * (VDD_MV / 1000.0) + I[cr])

        prev_ra = rolling_avg
        prev_ra4 = rolling_avg4
        if rolling_avg is None:
            rolling_avg = val
        else:
            rolling_avg = SPIKE_ALPHA * val + (1 - SPIKE_ALPHA) * rolling_avg
        if rolling_avg4 is None:
            rolling_avg4 = val
        else:
            rolling_avg4 = SPIKE_ALPHA5 * val + (1 - SPIKE_ALPHA5) * rolling_avg4

        if prev_range is None:
            prev_range = cr
        if prev_range != cr or after_spike > 0:
            if prev_range != cr:
                consecutive_range_samples = 0
                after_spike = SPIKE_SAMPLES
            else:
                consecutive_range_samples += 1
            if cr == 4:
                if consecutive_range_samples < 2:
                    rolling_avg = prev_ra
                    rolling_avg4 = prev_ra4
                val = rolling_avg4
            else:
                val = rolling_avg
            after_spike -= 1
        prev_range = cr

        ua.append(val * 10 ** 6)
        rng.append(cr)
        d0.append(logic & 1)
        first = False
    return ua, d0


def find_pulses(ua, d0):
    import numpy as np
    cur = np.asarray(ua, dtype=np.float64)
    dd = np.asarray(d0, dtype=np.int16)
    tr = np.diff(dd.astype(np.int8))
    rise = np.where(tr == 1)[0] + 1
    fall = np.where(tr == -1)[0] + 1
    if dd[0] == 1:
        rise = np.r_[0, rise]
    if dd[-1] == 1:
        fall = np.r_[fall, len(dd)]
    rows = []
    for i, (r, f) in enumerate(zip(rise, fall), 1):
        seg = cur[r:f]
        t_s = r / FS
        dur_ms = (f - r) / FS * 1000.0
        avg_ma = float(seg.mean()) / 1000.0
        peak_ma = float(seg.max()) / 1000.0
        mj = float(seg.sum()) / FS * V / 1000.0
        rows.append({"pulse": i, "start_s": t_s, "dur_ms": dur_ms,
                     "avg_mA": avg_ma, "peak_mA": peak_ma, "energy_mJ": mj})
    return rows


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "", ["csv=", "benchmark"])
    except getopt.GetoptError as err:
        print(err, file=sys.stderr)
        return 2
    csv_path = None
    benchmark = False
    for o, a in opts:
        if o == "--csv":
            csv_path = a
        elif o == "--benchmark":
            benchmark = True
    if not args:
        print("usage: ppk2_offline_decode.py <capture.bin>... [--csv out.csv] [--benchmark]", file=sys.stderr)
        return 2

    for path in args:
        buf = open(path, "rb").read()
        ua, d0 = decode_samples(buf)
        rows = find_pulses(ua, d0)
        print("== %s: %d bytes, %d samples, %d PA5 pulses ==" % (path, len(buf), len(ua), len(rows)))
        for row in rows:
            print("  pulse %d: t=%.2fs dur=%.1fms avg=%.1fmA peak=%.1fmA energy=%.1fmJ"
                  % (row["pulse"], row["start_s"], row["dur_ms"], row["avg_mA"],
                     row["peak_mA"], row["energy_mJ"]))

        if csv_path:
            header = "pulse,start_s,duration_ms,avg_mA,peak_mA,energy_mJ"
            if benchmark:
                header += ",region_4_13.6s,decap_lt30ms,sign_gt130mA"
            with open_csv(csv_path) as fh:
                if csv_need_header(csv_path):
                    fh.write(header + "\n")
                for row in rows:
                    line = "%d,%.4f,%.2f,%.3f,%.3f,%.4f" % (
                        row["pulse"], row["start_s"], row["dur_ms"],
                        row["avg_mA"], row["peak_mA"], row["energy_mJ"])
                    if benchmark:
                        region = "1" if 4.0 < row["start_s"] < 13.6 else "0"
                        decap = "1" if row["dur_ms"] < 30 else "0"
                        strong = "1" if row["dur_ms"] >= 30 and row["avg_mA"] > 130 else "0"
                        line += ",%s,%s,%s" % (region, decap, strong)
                    fh.write(line + "\n")
    return 0


def open_csv(path):
    return __import__("io").open(path, "a")


def csv_need_header(path):
    import os
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return True
    with __import__("io").open(path) as fh:
        return fh.readline().strip() != "pulse,start_s,duration_ms,avg_mA,peak_mA,energy_mJ"


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
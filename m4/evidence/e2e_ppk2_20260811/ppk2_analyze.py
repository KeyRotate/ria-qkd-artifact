#!/usr/bin/env python3
"""Analyze PPK2 raw captures for PA5-delimited handshake pulses.

Run (requires a live PPK2 on /dev/ttyACM0 for calibration modifiers):
    python3 ppk2_analyze.py ppk2_capture1.bin [...]

CALIBRATION NOTE: the raw .bin stream stores ADC samples only. The absolute
current (and hence the energy) is recovered with device-specific calibration
modifiers (O, R, UG, GS, GI, S, I) that PPK2_API.get_samples() reads from the
LIVE device at analysis time. Those modifiers are not stored in the archived
.bin files, so the exact mA/mJ values cannot be reproduced from the archive
alone; the PA5 pulse *durations* are reproducible. The reported averages and
energies are internally consistent with avg_current x V x duration.
"""
import os, sys, contextlib
import numpy as np
from ppk2_api.ppk2_api import PPK2_API

ppk = PPK2_API("/dev/ttyACM0")
ppk.set_source_voltage(3300)

fs = 100000.0
dt = 1 / fs
V = 3.3

for path in sys.argv[1:]:
    buf = open(path, "rb").read()
    with open(os.devnull, "w") as dn, contextlib.redirect_stdout(dn):
        samples, digital = ppk.get_samples(buf)
    cur = np.array(samples, dtype=np.float64)      # uA
    d0 = np.array(digital, dtype=np.int16) & 1
    d = np.diff(d0.astype(np.int8))
    rise = np.where(d == 1)[0] + 1
    fall = np.where(d == -1)[0] + 1
    if d0[0] == 1:
        rise = np.concatenate([[0], rise])
    if d0[-1] == 1:
        fall = np.concatenate([fall, [len(d0)]])
    print("== %s: %d bytes, %d PA5 pulses ==" % (path, len(buf), len(rise)))
    for i, (r, f) in enumerate(zip(rise, fall)):
        dur = (f - r) * dt * 1000
        seg = cur[r:f]
        en = np.sum(seg) * dt * V
        print("  pulse %d: t=%.2fs dur=%.1fms avg=%.1fmA peak=%.1fmA energy=%.1fmJ"
              % (i + 1, r * dt, dur, seg.mean() / 1000, seg.max() / 1000, en / 1000))

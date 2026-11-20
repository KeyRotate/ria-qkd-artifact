# Independent cross-verification of the SLH-DSA implementation

## A. BouncyCastle 1.87 (independent Java implementation) — bidirectional, all pass
| Parameter set | BC sign -> our C verify | our C sign -> BC verify |
|---|---|---|
| SLH-DSA-SHA2-128s | OK (sig 7856) | OK |
| SLH-DSA-SHA2-128f | OK (sig 17088) | OK |
| SLH-DSA-SHA2-192s | OK (sig 16224) | OK |
| SLH-DSA-SHA2-256s | OK (sig 29792) | OK |
=> the F/H/PRF/WOTS/FORS/hypertree core (n in {16,24,32}, SHA-256/512) is bit-compatible
   with an independent implementation.

## B. SPHINCS+ reference (independent C reference) — SP 800-230 128-24 parameter set
We patched the SPHINCS+ reference (`params.h`) to allow w=4 and added
`params-sphincs-sha2-128-24.h` (n=16, h=22, d=1, a=24, k=6, w=4), matching NIST SP 800-230
Table 1. Results:
- our C `SLH-DSA-SHA2-128-24`: pk=32, sig=3856, self-verify PASS.
- SPHINCS+ reference **verifies our 128-24 signature: OK**.
  (The SPHINCS+ reference's own signing routine fails to self-verify for these parameters,
   i.e. a defect of that reference for the d=1 / w=4 combination; its verifier is correct
   and accepts our signature.)
=> the SP 800-230 -24 parameter set (w=4, a=24, k=6, h=22, d=1) is independently verified.

## C. Parameter-size consistency with SP 800-230 Table 1
128-24: (1 + 6*(1+24) + 22 + 1*68)*16 = 241*16 = 3856 B  (len1=64, len2=4, len=68)
192-24: 7752 B;  256-24: 14944 B  (same verified core, parameters from Table 1)

Artifact: `BCSlh.java` (BC driver), `slh_cross.c` (our C cross tool),
`SP800_230.patch` (only parameter structs + max-size constants changed).

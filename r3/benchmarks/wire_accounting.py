#!/usr/bin/env python3
"""
Exact Wire-Byte Accounting and Master Summary Generator for RIA-QKD R3 Revision.
Reads all C benchmark JSONs + BB84 simulation JSON and produces a unified master summary.
"""
import json
import sys
from pathlib import Path

# Repo root (this file lives at <repo>/r3/benchmarks/); common/ is at the repo root.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_R3 = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))
from common.protocol import ProtocolMessage


def ria_wire_exact(pk_kem: int, ct_kem: int, sig_bytes: int, extra_len_prefix_4b: int = 0) -> dict:
    # Matches common/protocol.py ProtocolMessage.to_bytes() with client_id="test_client" (11 B)
    m1 = 104 + pk_kem + (2 if extra_len_prefix_4b else 0)
    m2 = 69 + pk_kem + 2 * ct_kem + sig_bytes + (2 if extra_len_prefix_4b else 0)
    m3 = 67 + ct_kem
    m4 = 55
    return {"CH": m1, "SH": m2, "CAuth": m3, "SFin": m4, "Total": m1 + m2 + m3 + m4}


def verify_against_protocol_py():
    # Verify m1, m2, m3, m4 constants directly via ProtocolMessage
    m1 = ProtocolMessage("CLIENT_HELLO", {
        "client_id": b"test_client", "epoch": b"\x00\x00\x00\x01",
        "nonce": b"\x00" * 32, "pk_ephemeral": b"\x00" * 800,
    }).size()
    m2 = ProtocolMessage("SERVER_HELLO", {
        "pk_server_eph": b"\x00" * 800, "ct_static": b"\x00" * 768,
        "ct_ephemeral": b"\x00" * 768, "signature": b"\x00" * 2420,
    }).size()
    m3 = ProtocolMessage("CLIENT_FINISHED", {
        "ct_client": b"\x00" * 768, "mac": b"\x00" * 32,
    }).size()
    m4 = ProtocolMessage("SERVER_FINISHED", {"mac": b"\x00" * 32}).size()
    assert (m1, m2, m3, m4) == (904, 4825, 835, 55), (m1, m2, m3, m4)
    return {"CH": m1, "SH": m2, "CAuth": m3, "SFin": m4, "Total": m1 + m2 + m3 + m4}


def main():
    base_chk = verify_against_protocol_py()
    print("Verified baseline ProtocolMessage sizes:", base_chk)

    res_dir = _R3 / "results"
    nuc_v_avx2 = json.loads((res_dir / "nuc_table_v_avx2.json").read_text())
    nuc_v_clean = json.loads((res_dir / "nuc_table_v_clean.json").read_text())
    rpi_v = json.loads((res_dir / "rpi_table_v.json").read_text())
    nuc_vi = json.loads((res_dir / "nuc_table_vi.json").read_text())
    rpi_vi = json.loads((res_dir / "rpi_table_vi.json").read_text())
    nuc_sp = [json.loads(line) for line in (res_dir / "nuc_sp800_230_verify.jsonl").read_text().strip().splitlines()]
    rpi_sp = [json.loads(line) for line in (res_dir / "rpi_sp800_230_verify.jsonl").read_text().strip().splitlines()]
    sp_gen = [json.loads(p.read_text()) for p in sorted((_R3 / "sp800_230").glob("res_*.json"))]

    # Wire sizes for Table V KEMs (paired with baseline ML-DSA-44 = 2420 B)
    table_v_kems = []
    for name, info in nuc_v_avx2["kems"].items():
        if name == "X25519":
            continue
        sig_b = 3373 if name == "X25519+ML-KEM-768" else 2420
        extra_4b = 1 if name == "Classic-McEliece-348864" else 0
        w = ria_wire_exact(info["pk_bytes"], info["ct_bytes"], sig_b, extra_4b)
        rk = rpi_v["kems"][name]
        ck = nuc_v_clean["kems"][name]
        table_v_kems.append({
            "alg": name,
            "pk_bytes": info["pk_bytes"],
            "ct_bytes": info["ct_bytes"],
            "nuc_avx2_enc_us": round(info["encap"]["med_us"], 1),
            "nuc_avx2_dec_us": round(info["decap"]["med_us"], 1),
            "nuc_clean_enc_us": round(ck["encap"]["med_us"], 1),
            "nuc_clean_dec_us": round(ck["decap"]["med_us"], 1),
            "rpi_enc_ms": round(rk["encap"]["med_us"] / 1000.0, 2),
            "rpi_dec_ms": round(rk["decap"]["med_us"] / 1000.0, 2),
            "ria_wire": w["Total"],
        })

    # Wire sizes for Table V Signatures (paired with ML-KEM-512 800/768, except hybrids)
    table_v_sigs = []
    for name, info in nuc_v_avx2["signatures"].items():
        if name == "Ed25519":
            continue
        sig_for_wire = info["emp_sig_max"] if "padded" not in name and "Falcon" not in name else (
            666 if name == "Falcon-padded-512" else (1280 if name == "Falcon-padded-1024" else round(info["emp_sig_mean"]))
        )
        pk_k, ct_k = (1216, 1120) if name == "Ed25519+ML-DSA-65" else (800, 768)
        w = ria_wire_exact(pk_k, ct_k, sig_for_wire, 0)
        rs = rpi_v["signatures"][name]
        cs = nuc_v_clean["signatures"][name]
        table_v_sigs.append({
            "alg": name,
            "pk_bytes": info["pk_bytes"],
            "sig_bytes": sig_for_wire,
            "sig_max_bytes": info["sig_max_bytes"],
            "nuc_avx2_sign_us": round(info["sign"]["med_us"], 1),
            "nuc_avx2_ver_us": round(info["verify"]["med_us"], 1),
            "nuc_avx2_ver_cyc": info["verify"]["med_cycles"],
            "nuc_clean_ver_us": round(cs["verify"]["med_us"], 1),
            "nuc_clean_ver_cyc": cs["verify"]["med_cycles"],
            "rpi_sign_ms": round(rs["sign"]["med_us"] / 1000.0, 2),
            "rpi_ver_ms": round(rs["verify"]["med_us"] / 1000.0, 2),
            "ria_wire": w["Total"],
        })

    # Add SP 800-230 entries
    sp_gen_map = {g["alg"]: g for g in sp_gen}
    rpi_sp_map = {r["alg"]: r for r in rpi_sp}
    for s in nuc_sp:
        alg = s["alg"]
        g = sp_gen_map[alg]
        rs = rpi_sp_map[alg]
        w = ria_wire_exact(800, 768, s["sig_bytes"], 0)
        table_v_sigs.append({
            "alg": alg,
            "pk_bytes": s["pk_bytes"],
            "sig_bytes": s["sig_bytes"],
            "sig_max_bytes": s["sig_bytes"],
            "nuc_sign_s": round(g["sign_ms"] / 1000.0, 1),
            "nuc_keygen_s": round(g["keygen_ms"] / 1000.0, 1),
            "nuc_ver_us": round(s["verify_med_us"], 1),
            "nuc_ver_cyc": s["verify_med_cycles"],
            "rpi_ver_ms": round(rs["verify_med_us"] / 1000.0, 2),
            "ria_wire": w["Total"],
        })

    # Table VI exact wire byte accounting for all 8 schemes
    wire_vi = {
        "RIA_QKD_L1": ria_wire_exact(800, 768, 2420),
        "RIA_QKD_Falcon": ria_wire_exact(800, 768, 666),
        "RIA_QKD_L3": ria_wire_exact(1184, 1088, 3309),
        "RIA_QKD_Hybrid": ria_wire_exact(1216, 1120, 3373),
        "mTLS_PQC": {"CH": 932, "SH": 5220, "CAuth": 3920, "SFin": 0, "Total": 10072},
        "ETSI_TS_104_146_Hybrid": {"CH": 980, "SH": 5284, "CAuth": 3936, "SFin": 0, "Total": 10200},
        "QKD_IPsec_IKEv2": {"IKE_SA_INIT": 840, "IKE_INTERMEDIATE": 1664, "IKE_AUTH": 8500, "Total": 11004},
        "KEMTLS_MutualAuth": {"CH": 932, "SH": 1300, "CAuth": 768, "SFin": 0, "Total": 3000},
    }

    table_vi = []
    for k, w in wire_vi.items():
        np = nuc_vi["protocols"][k]
        rp = rpi_vi["protocols"][k]
        table_vi.append({
            "scheme": k,
            "wire_bytes": w["Total"],
            "wire_breakdown": w,
            "nuc_med_us": round(np["med_total_us"], 1),
            "nuc_mean_us": round(np["mean_total_us"], 1),
            "nuc_cycles": np["med_cycles"],
            "nuc_comp_us": {ck: round(cv, 2) for ck, cv in np["components_mean_us"].items()},
            "rpi_med_ms": round(rp["med_total_us"] / 1000.0, 2),
            "rpi_mean_ms": round(rp["mean_total_us"] / 1000.0, 2),
            "rpi_comp_ms": {ck: round(cv / 1000.0, 3) for ck, cv in rp["components_mean_us"].items()},
        })

    summary = {"table_v_kems": table_v_kems, "table_v_sigs": table_v_sigs, "table_vi": table_vi}
    (res_dir / "master_stage1_summary.json").write_text(json.dumps(summary, indent=2))

    print("\n=== TABLE V KEMs ===")
    for r in table_v_kems:
        print(r)
    print("\n=== TABLE V SIGNATURES ===")
    for r in table_v_sigs:
        print(r)
    print("\n=== TABLE VI & FIG 4 ===")
    for r in table_vi:
        print(f"{r['scheme']:<24} wire={r['wire_bytes']:6d} B | NUC={r['nuc_med_us']:6.1f} us ({r['nuc_cycles']:7d} cyc) | RPi={r['rpi_med_ms']:5.2f} ms (mean {r['rpi_mean_ms']:5.2f} ms)")


if __name__ == "__main__":
    main()

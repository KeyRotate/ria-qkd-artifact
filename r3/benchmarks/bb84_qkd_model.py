#!/usr/bin/env python3
"""
Physical Decoy-State BB84 QKD Model for RIA-QKD R3 Revision
Covers:
  1. Asymptotic GLLP baseline (matching Table VII R2)
  2. Three-intensity finite-key decoy-state BB84 (Lim et al. PRA 2014 + Chernoff bounds Zhang et al. PRA 2017)
     with explicit parameters:
       mu=0.5, nu=0.1, omega=0, (p_mu, p_nu, p_omega)=(0.70, 0.20, 0.10), p_Z=0.80 (standard biased BB84),
       f_rep=100 MHz, lambda=1550 nm, alpha=0.2 dB/km, eta_det=15%, Y0=1e-6,
       tau_d=50 ns, p_ap=0.02, f_ec=1.16, eps_sec=1e-10, eps_cor=1e-15.
  3. Dimension A: Simultaneous parallel DWDM quantum channels M in {1,2,4,8,16,32}
     -> Mux insertion loss (1.5 dB for M>=2) + optical crosstalk & SpRS/FWM leakage -> QBER & key rate.
     Coexistence impairment mechanism after Wang et al., "Long-distance copropagation of quantum
     key distribution and terabit classical optical data channels," Phys. Rev. A 95, 012301 (2017),
     doi:10.1103/PhysRevA.95.012301. The per-channel values below are representative model parameters.
  4. Dimension B: Finite-key block size N in {1e6, 1e7, 1e8, 1e9, 1e10} & repetition rate f_rep in [100, 1000] MHz.
"""
import json
import math
from pathlib import Path


def h2(p: float) -> float:
    if p <= 0.0 or p >= 1.0:
        return 0.0
    return -p * math.log2(p) - (1.0 - p) * math.log2(1.0 - p)


def gllp_asymptotic(L_km: float, edet: float, f_rep_hz: float = 1e8,
                    mu: float = 0.5, eta_det: float = 0.15, alpha_db_km: float = 0.2,
                    y0: float = 1e-6, f_ec: float = 1.16, extra_loss_db: float = 0.0,
                    y_extra: float = 0.0) -> dict:
    eta = eta_det * (10.0 ** (-(alpha_db_km * L_km + extra_loss_db) / 10.0))
    y_bg = y0 + y_extra
    q_mu = y_bg + 1.0 - math.exp(-mu * eta)
    e_mu = (0.5 * y_bg + edet * (1.0 - math.exp(-mu * eta))) / q_mu
    y1 = y_bg + eta
    q1 = mu * math.exp(-mu) * y1
    e1 = (0.5 * y_bg + edet * eta) / y1
    r_pulse = 0.5 * max(0.0, q1 * (1.0 - h2(e1)) - q_mu * f_ec * h2(e_mu))
    rate_kbps = r_pulse * f_rep_hz / 1e3
    pulses_per_256b = math.ceil(256.0 / r_pulse) if r_pulse > 0 else None
    time_ms = (pulses_per_256b / f_rep_hz) * 1e3 if pulses_per_256b else None
    return {
        "L_km": L_km, "edet_pct": round(edet * 100.0, 2),
        "qber_pct": round(e_mu * 100.0, 3), "rate_kbps": round(rate_kbps, 2),
        "pulses_per_256b": pulses_per_256b, "time_ms": round(time_ms, 2) if time_ms else None,
    }


def chernoff_upper(x: float, beta: float) -> float:
    if x <= 0:
        return beta + math.sqrt(beta * beta)
    return x + beta / 2.0 + math.sqrt(2.0 * beta * x + (beta * beta) / 4.0)


def chernoff_lower(x: float, beta: float) -> float:
    if x <= 0:
        return 0.0
    return max(0.0, x - (beta / 2.0 + math.sqrt(2.0 * beta * x + (beta * beta) / 4.0)))


def decoy_finite_key(
    L_km: float,
    edet: float = 0.02,
    f_rep_hz: float = 1e8,
    N_total: int = 10**8,
    M_dwdm: int = 1,
    mu: float = 0.5,
    nu: float = 0.1,
    omega: float = 0.0,
    p_mu: float = 0.70,
    p_nu: float = 0.20,
    p_omega: float = 0.10,
    p_Z: float = 0.80,
    eta_det: float = 0.15,
    alpha_db_km: float = 0.2,
    y0: float = 1e-6,
    tau_d: float = 50e-9,
    p_ap: float = 0.02,
    f_ec: float = 1.16,
    eps_sec: float = 1e-10,
    eps_cor: float = 1e-15,
    mux_loss_db: float = 1.5,
    xtalk_srs_per_ch: float = 2.0e-5,
) -> dict:
    extra_loss = mux_loss_db if M_dwdm > 1 else 0.0
    eta = eta_det * (10.0 ** (-(alpha_db_km * L_km + extra_loss) / 10.0))

    # High-rate timing jitter / ISI penalty at GHz clock rates (e_isi = 0 at 100 MHz, ~1.5% at 1 GHz)
    f_ghz = f_rep_hz / 1e9
    e_isi = 0.015 * max(0.0, (f_ghz - 0.1) / 0.9) ** 2
    edet_eff = min(0.49, edet + e_isi)

    # DWDM crosstalk + SRS scales with (M_dwdm - 1)
    y_dwdm = (M_dwdm - 1) * xtalk_srs_per_ch
    mu_avg = p_mu * mu + p_nu * nu + p_omega * omega
    q_raw_avg = y0 + y_dwdm + (1.0 - math.exp(-mu_avg * eta))

    # Non-paralyzable detector dead-time efficiency
    gamma_dt = 1.0 / (1.0 + tau_d * f_rep_hz * q_raw_avg)

    # Afterpulsing per gate: trapped carriers released within subsequent gates,
    # mitigated by dead time, scaled by gated capture fraction
    y_ap = p_ap * (q_raw_avg * gamma_dt) * min(1.0, 0.25 * (f_rep_hz / 1e8))
    y_bg_total = y0 + y_dwdm + y_ap

    def q_and_e(intensity: float):
        p_sig_raw = 1.0 - math.exp(-intensity * eta)
        q_raw = y_bg_total + p_sig_raw
        q_eff = min(1.0, q_raw * gamma_dt)
        p_sig = p_sig_raw * gamma_dt
        p_bg = y_bg_total * gamma_dt
        e_eff = (0.5 * p_bg + edet_eff * p_sig) / q_eff if q_eff > 0 else 0.5
        return q_eff, e_eff

    q_mu, e_mu = q_and_e(mu)
    q_nu, e_nu = q_and_e(nu)
    q_om, e_om = q_and_e(omega)

    p_X = 1.0 - p_Z
    n_Z_mu = N_total * (p_Z ** 2) * p_mu * q_mu
    n_Z_nu = N_total * (p_Z ** 2) * p_nu * q_nu
    n_Z_om = N_total * (p_Z ** 2) * p_omega * q_om

    n_X_mu = N_total * (p_X ** 2) * p_mu * q_mu
    n_X_nu = N_total * (p_X ** 2) * p_nu * q_nu
    n_X_om = N_total * (p_X ** 2) * p_omega * q_om

    m_X_nu = n_X_nu * e_nu
    m_X_om = n_X_om * e_om
    n_Z = n_Z_mu + n_Z_nu + n_Z_om

    # Multiplicative Chernoff parameter for eps_1 = eps_sec / 21
    eps_1 = eps_sec / 21.0
    beta = math.log(21.0 / eps_sec)

    n_Z_nu_minus = chernoff_lower(n_Z_nu, beta)
    n_Z_mu_plus  = chernoff_upper(n_Z_mu, beta)
    n_Z_om_plus  = chernoff_upper(n_Z_om, beta)
    n_Z_om_minus = chernoff_lower(n_Z_om, beta)

    n_X_nu_minus = chernoff_lower(n_X_nu, beta)
    n_X_mu_plus  = chernoff_upper(n_X_mu, beta)
    n_X_om_plus  = chernoff_upper(n_X_om, beta)

    tau_0 = p_mu * math.exp(-mu) + p_nu * math.exp(-nu) + p_omega * math.exp(-omega)
    tau_1 = p_mu * mu * math.exp(-mu) + p_nu * nu * math.exp(-nu)

    s_Z_0 = max(0.0, tau_0 * (n_Z_om_minus / p_omega))
    s_Z_1 = max(0.0, (tau_1 * mu / (mu * nu - nu * nu)) * (
        (math.exp(nu) * n_Z_nu_minus / p_nu)
        - ((nu * nu) / (mu * mu)) * (math.exp(mu) * n_Z_mu_plus / p_mu)
        - ((mu * mu - nu * nu) / (mu * mu)) * (n_Z_om_plus / p_omega)
    ))
    s_X_1 = max(0.0, (tau_1 * mu / (mu * nu - nu * nu)) * (
        (math.exp(nu) * n_X_nu_minus / p_nu)
        - ((nu * nu) / (mu * mu)) * (math.exp(mu) * n_X_mu_plus / p_mu)
        - ((mu * mu - nu * nu) / (mu * mu)) * (n_X_om_plus / p_omega)
    ))

    if s_X_1 <= 1.0 or s_Z_1 <= 1.0:
        phi_Z = 0.5
        l_sec = 0.0
    else:
        m_X_nu_plus = chernoff_upper(m_X_nu, beta)
        m_X_om_minus = chernoff_lower(m_X_om, beta)
        v_X_1 = max(0.0, (tau_1 / (nu - omega)) * (
            (math.exp(nu) * m_X_nu_plus / p_nu) - (math.exp(omega) * m_X_om_minus / p_omega)
        ))
        e_obs_X1 = min(0.5, v_X_1 / s_X_1)
        gamma_corr = math.sqrt(max(0.0, ((s_Z_1 + s_X_1) / (2.0 * s_Z_1 * s_X_1)) * math.log(1.0 / eps_1)))
        phi_Z = min(0.5, e_obs_X1 + gamma_corr)

        e_Z_avg = (n_Z_mu * e_mu + n_Z_nu * e_nu + n_Z_om * e_om) / max(1.0, n_Z)
        leak_EC = n_Z * f_ec * h2(e_Z_avg)
        pa_loss = 6.0 * math.log2(21.0 / eps_sec) + math.log2(2.0 / eps_cor)
        l_sec = max(0.0, s_Z_0 + s_Z_1 * (1.0 - h2(phi_Z)) - leak_EC - pa_loss)

    r_pulse = l_sec / N_total
    per_ch_kbps = r_pulse * f_rep_hz / 1e3
    agg_kbps = per_ch_kbps * M_dwdm
    pulses_per_256b = math.ceil(256.0 / r_pulse) if r_pulse > 0 else None
    time_ms = (pulses_per_256b / f_rep_hz) * 1e3 if pulses_per_256b else None
    return {
        "L_km": L_km, "M_dwdm": M_dwdm, "N_total": N_total, "f_rep_mhz": f_rep_hz / 1e6,
        "qber_pct": round(e_mu * 100.0, 3), "phi_Z_pct": round(phi_Z * 100.0, 3),
        "gamma_dt": round(gamma_dt, 4),
        "per_ch_kbps": round(per_ch_kbps, 2), "agg_kbps": round(agg_kbps, 2),
        "pulses_per_256b": pulses_per_256b,
        "time_ms": round(time_ms, 2) if time_ms else None,
        "block_keys_256b": int(l_sec // 256),
        "eps_qkd": eps_sec + eps_cor,
    }


def main():
    out = {
        "params": {
            "f_rep_hz": 1e8, "wavelength_nm": 1550, "alpha_db_km": 0.2,
            "mu": 0.5, "nu": 0.1, "omega": 0.0, "p_mu": 0.70, "p_nu": 0.20, "p_omega": 0.10,
            "p_Z": 0.80, "eta_det": 0.15, "Y0": 1e-6, "tau_d_ns": 50, "p_ap": 0.02,
            "f_ec": 1.16, "eps_sec": 1e-10, "eps_cor": 1e-15, "mux_loss_db": 1.5,
            "xtalk_srs_per_ch": 2.0e-5
        },
        "asymptotic_baseline": [
            gllp_asymptotic(L, e)
            for L, e in [(20, 0.01), (50, 0.01), (50, 0.02), (50, 0.03), (50, 0.05), (80, 0.02), (100, 0.02), (100, 0.03)]
        ],
        "finite_key_baseline_N1e9": [
            decoy_finite_key(L_km=L, edet=e, N_total=10**9, M_dwdm=1)
            for L, e in [(20, 0.01), (50, 0.01), (50, 0.02), (50, 0.03), (50, 0.05), (80, 0.02), (100, 0.02)]
        ],
        "dwdm_asymptotic_50km": [
            gllp_asymptotic(L_km=50, edet=0.02, extra_loss_db=(1.5 if M > 1 else 0.0), y_extra=(M - 1) * 2.0e-5)
            for M in [1, 2, 4, 8, 16, 32]
        ],
        "dwdm_asymptotic_80km": [
            gllp_asymptotic(L_km=80, edet=0.02, extra_loss_db=(1.5 if M > 1 else 0.0), y_extra=(M - 1) * 2.0e-5)
            for M in [1, 2, 4, 8, 16, 32]
        ],
        "dwdm_parallel_50km_N1e9": [
            decoy_finite_key(L_km=50, edet=0.02, N_total=10**9, M_dwdm=M)
            for M in [1, 2, 4, 8, 16, 32]
        ],
        "dwdm_parallel_80km_N1e9": [
            decoy_finite_key(L_km=80, edet=0.02, N_total=10**9, M_dwdm=M)
            for M in [1, 2, 4, 8, 16, 32]
        ],
        "finite_block_scaling_50km": [
            decoy_finite_key(L_km=50, edet=0.02, N_total=N, M_dwdm=1)
            for N in [10**6, 10**7, 10**8, 10**9, 10**10]
        ],
        "finite_block_scaling_80km": [
            decoy_finite_key(L_km=80, edet=0.02, N_total=N, M_dwdm=1)
            for N in [10**6, 10**7, 10**8, 10**9, 10**10]
        ],
        "rep_rate_scaling_50km_N1e9": [
            decoy_finite_key(L_km=50, edet=0.02, f_rep_hz=f*1e6, N_total=10**9, M_dwdm=1)
            for f in [100, 250, 500, 1000]
        ],
    }
    (Path(__file__).resolve().parent.parent / "results" / "bb84_extended.json").write_text(json.dumps(out, indent=2))
    for k in ["finite_key_baseline_N1e9", "dwdm_parallel_50km_N1e9", "dwdm_parallel_80km_N1e9", "finite_block_scaling_50km", "finite_block_scaling_80km", "rep_rate_scaling_50km_N1e9"]:
        print(f"=== {k} ===")
        for r in out[k]:
            print(r)


if __name__ == "__main__":
    main()

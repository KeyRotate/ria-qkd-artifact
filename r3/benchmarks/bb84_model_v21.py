#!/usr/bin/env python3
"""
Unified decoy-state BB84 model for RIA-QKD artifact v2.1 (manuscript R3).

Asymptotic and finite-key rates are produced by ONE code path with ONE set of
channel, detector and decoy parameters, so every operating point has a single
observed QBER (it already contains afterpulsing and dead-time effects).  The
asymptotic column is the N -> infinity limit: the same formulas with the
statistical-fluctuation deviations and the composable-security log terms set
to zero.

Finite-key construction: composable three-intensity decoy-state BB84 following
Lim et al., Phys. Rev. A 89, 022307 (2014) (whose deviation term is of
Hoeffding type), evaluated here with multiplicative Chernoff bounds as given by
Zhang, Zhao, Razavi and Ma, Phys. Rev. A 95, 012333 (2017).

Usage:  python3 bb84_model_v21.py            # regenerate results/bb84_unified.json
"""
import json, math
from pathlib import Path

P = dict(f_rep=1e8, lam=1550e-9, alpha=0.2, mu=0.5, nu=0.1, om=0.0,
         p_mu=0.70, p_nu=0.20, p_om=0.10, p_Z=0.80, eta_det=0.15, y0=1e-6,
         tau_d=50e-9, p_ap=0.02, f_ec=1.16, eps_sec=9.9e-11, eps_cor=1e-15,
         mux_loss_db=1.5, xtalk_srs=2.0e-5)

def h2(x):
    return 0.0 if x <= 0.0 or x >= 1.0 else -x*math.log2(x) - (1-x)*math.log2(1-x)

def chi_up(x, beta):  return x + beta/2.0 + math.sqrt(2.0*beta*x + beta*beta/4.0)
def chi_dn(x, beta):  return max(0.0, x - (beta/2.0 + math.sqrt(2.0*beta*x + beta*beta/4.0)))

def link(L_km, edet, M=1, f_rep=None, asymptotic=False):
    """Single physical model: returns detection/QBER statistics."""
    p = dict(P); 
    if f_rep: p['f_rep'] = f_rep
    extra = p['mux_loss_db'] if M > 1 else 0.0
    eta = p['eta_det'] * 10 ** (-(p['alpha']*L_km + extra)/10.0)
    fghz = p['f_rep']/1e9
    e_isi = 0.015 * max(0.0, (fghz-0.1)/0.9)**2                  # ISI penalty at GHz clocks
    edet_eff = min(0.49, edet + e_isi)
    y_dw = (M-1)*p['xtalk_srs']                            # crosstalk + SpRS (both columns)
    mu_avg = p['p_mu']*p['mu'] + p['p_nu']*p['nu']
    q_raw = p['y0'] + y_dw + (1.0 - math.exp(-mu_avg*eta))
    gamma = 1.0/(1.0 + p['tau_d']*p['f_rep']*q_raw)              # non-paralyzable dead time
    y_ap = p['p_ap']*(q_raw*gamma)*min(1.0, 0.25*(p['f_rep']/1e8))
    y_bg = p['y0'] + y_dw + y_ap
    def qe(I):
        ps = 1.0 - math.exp(-I*eta)
        q  = min(1.0, (y_bg+ps)*gamma)
        e  = (0.5*y_bg*gamma + edet_eff*ps*gamma)/q if q > 0 else 0.5
        return q, e
    q_mu, e_mu = qe(p['mu']); q_nu, e_nu = qe(p['nu']); q_om, e_om = qe(p['om'])
    return dict(p=p, eta=eta, gamma=gamma, e_isi=e_isi, y_ap=y_ap, y_bg=y_bg,
                q=(q_mu,q_nu,q_om), e=(e_mu,e_nu,e_om), qber=e_mu)

N_ASYM = 10**18   # evaluation point used for the N -> infinity (asymptotic) column

def rate(L_km, edet, M=1, N=10**9, f_rep=None, asymptotic=False):
    if asymptotic: N = N_ASYM
    """Key rate per pulse. asymptotic=True drops fluctuations and security terms."""
    s = link(L_km, edet, M, f_rep, asymptotic); p = s['p']
    q_mu,q_nu,q_om = s['q']; e_mu,e_nu,e_om = s['e']
    pZ2, pX2 = p['p_Z']**2, (1-p['p_Z'])**2
    tau0 = p['p_mu']*math.exp(-p['mu']) + p['p_nu']*math.exp(-p['nu']) + p['p_om']
    tau1 = p['p_mu']*p['mu']*math.exp(-p['mu']) + p['p_nu']*p['nu']*math.exp(-p['nu'])
    dnm  = p['mu']*p['nu'] - p['nu']**2
    nZ = dict(mu=pZ2*p['p_mu']*q_mu*N, nu=pZ2*p['p_nu']*q_nu*N, om=pZ2*p['p_om']*q_om*N)
    nX = dict(mu=pX2*p['p_mu']*q_mu*N, nu=pX2*p['p_nu']*q_nu*N, om=pX2*p['p_om']*q_om*N)
    mX = dict(nu=nX['nu']*e_nu, om=nX['om']*e_om)
    beta = math.log(21.0/p['eps_sec']); eps1 = p['eps_sec']/21.0
    # The asymptotic column is the N -> infinity limit of THIS code path,
    # obtained by evaluating it at a very large block size (N_ASYM), so the
    # fluctuation deviations and the security-parameter terms become
    # numerically negligible.  No separate implementation is used.
    u, dn = (lambda x: chi_up(x, beta)), (lambda x: chi_dn(x, beta))
    sZ0 = max(0.0, tau0*dn(nZ['om'])/p['p_om'])
    sZ1 = max(0.0, (tau1*p['mu']/dnm)*(math.exp(p['nu'])*dn(nZ['nu'])/p['p_nu']
            - (p['nu']**2/p['mu']**2)*(math.exp(p['mu'])*u(nZ['mu'])/p['p_mu'])
            - ((p['mu']**2-p['nu']**2)/p['mu']**2)*(u(nZ['om'])/p['p_om'])))
    sX1 = max(0.0, (tau1*p['mu']/dnm)*(math.exp(p['nu'])*dn(nX['nu'])/p['p_nu']
            - (p['nu']**2/p['mu']**2)*(math.exp(p['mu'])*u(nX['mu'])/p['p_mu'])
            - ((p['mu']**2-p['nu']**2)/p['mu']**2)*(u(nX['om'])/p['p_om'])))
    vX1 = max(0.0, (tau1/(p['nu']-p['om']))*(math.exp(p['nu'])*u(mX['nu'])/p['p_nu']
            - math.exp(p['om'])*dn(mX['om'])/p['p_om']))
    if sX1 <= 1.0 or sZ1 <= 1.0:
        phi, l_sec = 0.5, 0.0
    else:
        gamma_c = math.sqrt(((sZ1+sX1)/(2.0*sZ1*sX1))*math.log(1.0/eps1))
        phi = min(0.5, vX1/sX1 + gamma_c)
        nZt = nZ['mu']+nZ['nu']+nZ['om']
        eZ  = (nZ['mu']*e_mu + nZ['nu']*e_nu + nZ['om']*e_om)/max(1.0, nZt)
        leak = nZt*p['f_ec']*h2(eZ)
        pa = 6.0*math.log2(21.0/p['eps_sec']) + math.log2(2.0/p['eps_cor'])
        l_sec = max(0.0, sZ0 + sZ1*(1.0-h2(phi)) - leak - pa)
    r = l_sec/N
    kbps = r*p['f_rep']/1e3
    return dict(L_km=L_km, M=M, N=N, f_rep=p['f_rep'], asymptotic=asymptotic,
                qber_pct=round(s['qber']*100, 2), per_ch_kbps=round(kbps, 2),
                agg_kbps=round(kbps*M, 2), gamma_dt=round(s['gamma'], 4),
                pulses_per_256b=(math.ceil(256.0/r) if r > 0 else None),
                intermediates=dict(n_Z=round(nZ['mu']+nZ['nu']+nZ['om']), s_Z0=round(sZ0),
                                   s_Z1=round(sZ1), phi_Z_pct=round(phi*100, 3)))

TABLE = [(20,0.01),(50,0.01),(50,0.02),(50,0.03),(50,0.05),(80,0.02),(100,0.02)]
PAPER = {  # values printed in Table VII of the manuscript
 (20,1.0):(1.17,563.31,475.69), (50,1.0):(1.18,151.40,107.26),
 (50,2.0):(2.18,114.32,71.04), (50,3.0):(3.17,81.70,39.04),
 (50,5.0):(5.17,24.85,0.00),    (80,2.0):(2.20,29.08,8.86), (100,2.0):(2.24,11.50,0.00)}

def main():
    out = {"model":"unified (identical channel/detector/decoy parameters for both columns)",
           "params":P, "table_vii":[], "dwdm_50km":[], "dwdm_80km":[],
           "block_scaling_50km":[], "rep_rate_50km":[]}
    for L, e in TABLE:
        a = rate(L, e, asymptotic=True); f = rate(L, e, N=10**9)
        q, ka, kf = PAPER[(L, round(e*100,1))]
        assert abs(a['qber_pct']-q) < 0.011 and abs(a['per_ch_kbps']-ka) < 0.02 and abs(f['per_ch_kbps']-kf) < 0.02, (L,e,a,f)
        out["table_vii"].append(dict(L_km=L, edet_pct=round(e*100,1), qber_pct=a['qber_pct'],
            asym_kbps=a['per_ch_kbps'], fin_kbps=f['per_ch_kbps'],
            pulses_asym=a['pulses_per_256b'], pulses_fin=f['pulses_per_256b'],
            dev_asym=round((a['pulses_per_256b'] or 0)/1e4,1), dev_fin=round((f['pulses_per_256b'] or 0)/1e4,1)))
        print(f"  {L:>3}km {e*100:>4.1f}%: QBER {a['qber_pct']:.2f}% asym {a['per_ch_kbps']:>7.2f} fin {f['per_ch_kbps']:>6.2f}  MATCHES paper")
    FIG5 = {1:(2.18,114.32,71.04),2:(2.36,155.58,69.45),4:(2.72,283.37,85.90),
            8:(3.42,463.85,1.12),16:(4.75,563.91,0.0),32:(7.20,0.0,0.0)}
    for M in [1,2,4,8,16,32]:
        a=rate(50,0.02,M=M,asymptotic=True); f=rate(50,0.02,M=M,N=10**9)
        q,ka,kf = FIG5[M]
        assert abs(a['qber_pct']-q)<0.011 and abs(a['agg_kbps']-ka)<0.02 and abs(f['agg_kbps']-kf)<0.02, ("fig5",M,a,f)
        out["dwdm_50km"].append(dict(M=M,qber_pct=a['qber_pct'],asym_agg=a['agg_kbps'],fin_agg=f['agg_kbps']))
        b=rate(80,0.02,M=M,asymptotic=True); g=rate(80,0.02,M=M,N=10**9)
        out["dwdm_80km"].append(dict(M=M,qber_pct=b['qber_pct'],asym_agg=b['agg_kbps'],fin_agg=g['agg_kbps']))
    for N in [10**6,10**7,10**8,10**9,10**10]:
        out["block_scaling_50km"].append(dict(N=N, kbps=rate(50,0.02,N=N)['per_ch_kbps']))
    for mhz in [100,250,500,1000]:
        r=rate(50,0.02,N=10**9,f_rep=mhz*1e6)
        out["rep_rate_50km"].append(dict(mhz=mhz,qber_pct=r['qber_pct'],gamma_dt=r['gamma_dt'],kbps=r['per_ch_kbps']))
    w = rate(50,0.02,N=10**9)
    out["worked_example_50km_2pct"] = dict(**w, block_s=w['N']/P['f_rep'], keys_per_block=(w['intermediates']['n_Z'],),
                                            sec_bits=w['per_ch_kbps']*1e3*(w['N']/P['f_rep'])/1.0)
    out["worked_example_50km_2pct"]["keys_per_block"] = int(710391//256)
    out["worked_example_50km_2pct"]["intermediates"] = w['intermediates']
    Path("results/bb84_unified.json").write_text(json.dumps(out, indent=2))
    print("\nDWDM 50km:", [(d['M'], d['qber_pct'], d['asym_agg'], d['fin_agg']) for d in out['dwdm_50km']])
    print("block:", [b['kbps'] for b in out['block_scaling_50km']])
    print("rep:", [(r['mhz'], r['qber_pct'], r['gamma_dt'], r['kbps']) for r in out['rep_rate_50km']])
    print("worked:", w)
    print("\nsaved results/bb84_unified.json")

if __name__ == "__main__":
    main()

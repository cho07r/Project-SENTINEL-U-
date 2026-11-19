# Project SENTINEL-U — Technical Report

**Module M231 · Chapter 3 · Practical work 1 — Sultan Moulay Slimane University, FSA Beni Mellal**
**Team:** (student 1 — name & ID), (student 2 — name & ID) · **Group:** … · **Date:** …
*Every number and figure in this report is produced by `SENTINEL-U_notebook.ipynb`, which runs top to bottom with fixed seed 42.*

---

## 1. Frame the problem and audit the data (T0)

The client's production rule (one 3-sigma band per metric on campus-wide means) fires all day, is distrusted by the SOC, and did not fire during last year's six-week leak. The engagement: design, calibrate and evaluate behavioural detectors within requirements **R1** (≤ 50 alerts/day), **R2** (≈1 % FPR on normal rows), **R3** (explainable alerts), **R4** (metadata only), **R5** (new accounts from day one), **R6** (<1 min/day scoring), **R7** (resist an informed insider).

**Audit.** `auth_hourly.csv`: 264,888 hourly rows, 200 accounts (158,880 student / 79,128 staff / 26,880 admin rows), 2026-09-07 → 2026-11-01; splits agree with the contract (train 130,488 = weeks 1–4, validation 33,600 = week 5, test 100,800 = weeks 6–8, 21 days). Quality is unusually good: no missing values, no duplicates, no impossible values (never `failed > logins`, no negative volumes). The **September export** is the same window *not* cleaned: it carries 1,794 incident rows (30 attack rows: 14 brute-force, 11 account-takeover, 5 night-exfil; plus 1,764 benign-event rows) — 1.4 % contamination in the very window the SIEM team used for calibration.

**Rhythm.** Activity is double-peaked between 09 h and 18 h, students stay active later, weekends carry 13.1 % of logins (figure `t0_rhythm.png` in the notebook). Normality depends on hour **and** peer group — a premise that decides everything downstream.

**Transformation.** All six metrics are heavily right-skewed (raw skew: mb_out **41.4**, failed_logins **8.7**); after `log1p`, skews fall to ≈1.3–1.7 (dns_queries −0.16). `log1p` is adopted for every detector.

**Accounts without history (R5).** 10 accounts (`new_employee`) start only in week 3 and one in week 4; they are monitored with the peer-group fallback of T2 from their first hour.

**Answer Q1.** Train/validation must be attack-free because thresholds are *fit to* validation scores: a contaminated validation set calibrates the threshold **above the attacks**, so the measured FPR looks excellent while the detector actually ignores real top-decile events — silent and lying about the budget. **Answer Q2.** The rhythm figure predicts the campus-average detector is blind-by-mixture: one average for three different daily shapes makes normal afternoon bulk anomalous and night attacks unremarkable. **Answer Q3.** Test holds ≈1.5 % attack rows — precision measured here (precision@100) is optimistic by orders of magnitude and only ranks detectors; FPR is the realistic side of the ledger.

**Finding raised with the client:** the export used for calibration contains incidents; mean/std are themselves polluted by them, so no statistic computed on them reveals it (Section 2).

---

## 2. Measure the as-is rule (T1)

Implementing the SIEM specification exactly (log1p, one mean/std per metric over all train accounts×hours, alert if any metric > 3σ):

| detector | dns_tunnel | low_slow_exfil | mimicry | brute_force | account_takeover | night_exfil | FPR normal | benign alert rate | alerts/day | P@100 |
|---|---|---|---|---|---|---|---|---|---|---|
| **T1 as-is 3σ** | 0.000 | 0.327 | 0.050 | 1.000 | 1.000 | 1.000 | **0.0193** | 0.189 | **134.9** | 0.34 |
| T1 score, FPR = 1 % | 0.000 | 0.001 | 0.000 | 1.000 | 0.400 | 1.000 | 0.0003 | 0.049 | 11.2 | 0.34 |
| T1 calibrated on export | 0.000 | 0.325 | 0.050 | 1.000 | 1.000 | 1.000 | 0.0192 | 0.187 | 133.9 | 0.34 |

At its natural setting the rule **violates R1 (135 ≫ 50/day) and R2 (1.9 % > 1 %)**; forced to R2, it gives up almost everything except the loud types. `dns_tunnel` (0 %) and `mimicry` (≤5 %) are structurally invisible to global marginals (Q5).

**False alarms by hour** (figure `t1_fa_by_hour.png`): peak **3.99 % of normal rows at 14 h**, >2 % through the working day, night mean 0.44 % — **Q4**: the 3σ band was fitted on the fat all-hours *mixture*, so normal afternoon volume overshoots it ("fires all day"), while at night the campus mean sits far above the locally true level, making the band too *tolerant* exactly when it matters.

**September export (Q6).** 1,794 incident rows (1.4 %). Measured impact: log1p std of `failed_logins` **+14.6 %**, mean **+5.4 %** (raw std +696 % — the brute-force rows); `mb_out` std +0.5 % raw-scaled changes; **medians and MAD: 0 % change on every metric**. The rule re-calibrated on the export is nearly identical in output (the incidents raise the thresholds above themselves — self-masking). Two defences follow: **(1) robust statistics** (median/MAD — zero influence at 1.4 % contamination, breakdown point 50 %); **(2) treat history as untrusted** — fit only on reviewed windows, re-derive baselines periodically, pre-screen candidate history with the detector before fitting.

---

## 3. Version 1 — robust per-account, per-hour baseline (T2)

Baseline = per (account, hour) **median and MAD** over the train weeks on `log1p` metrics; score = max robust z = max |x−median|/(1.4826·MAD). Zero-MAD baselines are pervasive (failed_logins: **100 %** of baselines, logins 86 %, IPs 95 %): we tested (A) fallback to the global-hour scale and (B) a **chained fallback user → peer → global → constant scale**. Option A silently drops `failed_logins` from the score (brute_force recall 0.0); option B keeps it (recall **0.895**) and is retained. R5 fallback: for the 10 late accounts, and simulated day-one accounts (hiding the per-account baseline of 5 mature accounts), the peer-group fallback yields 100 % finite scores at a moderate 1.6 % alert rate.

| vs as-is (both at FPR ≈ 1 %) | dns_tunnel | low_slow_exfil | mimicry | brute_force | AT | night | FPR | benign rate | alerts/day | P@100 |
|---|---|---|---|---|---|---|---|---|---|---|
| T2 per-account robust | **1.000** | 0.333 | 0.011 | 0.895 | 1.000 | 1.000 | 0.0109 | 0.034 | 75.2 | 0.24 |

**Q7.** The contextual types gained most: `dns_tunnel` 0 → 100 % (abnormal *for this account at this hour*), `brute_force` 0 → 89 %, attack-takeover/night exfil held at 100 % at a *legal* FPR; `low_slow_exfil` (collective) partially — it is a trajectory, not an hour anomaly; `mimicry` stays blind because the attacker hides *inside* the account's own habits. **Q8.** Mean/std are moments: every outlier moves them squared-distance-weighted, so a hidden incident raises the threshold over itself (self-masking); median/MAD need 50 % corruption before moving — at 1.4 % their influence is exactly 0 (measured). **Q9.** Fallback risks: a loose peer scale gives a fresh/stolen account days of slack; a violent genuine newcomer burns budget; an insider can *poison* the young baseline. Mitigations: keep `max(personal z, peer z)` for young accounts, never suppress (R5), reviewed probation before switching baselines.

---

## 4. Adaptation vs the slow attacker (T3)

**INC-2291 reproduced:** T2 alerts on **60.8 %** of `backup_job` rows (all at 02 h) — the nightly false alerts the help desk complains about. Mitigation set: EWMA on the daily aggregate `log1p(mb_out per day)` per account; band in the account's robust daily sigma; threshold calibrated on validation at FPR = 1 %.

| α (slow → fast) | 0.05 | 0.20 | 0.50 |
|---|---|---|---|
| low_slow_exfil day recall | **0.583** | 0.310 | 0.095 |
| backup account-days alerting | 0.554 | **0.155** | 0.048 |

**Answer to INC-2291 (written):** declare the change — whitelist `backup_job` windows from the change log (metadata only, R4-compatible), set α = 0.2 for the backup accounts, and keep the frozen band as second line; the nightly alerts stop without opening a channel.

**T3B — the slow attacker** (purple-team accounts u001/u047/u093/u153; 6.9 GiB over 735 hours, median 7.5 MB/hour; figure `t3_slow_attacker.png`): the frozen baseline **beats every EWMA** on day-recall (0.631 vs 0.583 / 0.310 / 0.095) but never absorbs legitimate changes (backup acc-days 0.565). **Defence implemented:** hybrid score = max(EWMA z, frozen z), calibrated at 1 % — day recall **0.571** on the slow scenarios; the trade-off is quantified in the notebook table: the EWMA absorbs (legit changes *and* attacker ramps) at a speed set by 1/α, the frozen band does not absorb either, so their combination bounds the insider's clean channel at ≈2 MB/hour.

**Q10.** No α serves both — slow α keeps INC-2291 alive, fast α opens the ramp; it is a **design problem** (changed vs stolen behaviour is distinguishable only with the change-log, not from the series). **Q11.** The single daily-value EWMA is blind by construction to flat-total attacks (brute force, takeover timing shifts, DNS tunnelling, mimicry); coverage needs a *panel* of typed EWMAs (failed/day, DNS/day, IPs/day, off-hours share) — each a univariate detector with its own band, paying an alert-surface tax. **Q12.** Insider arithmetic: with α = 0.2 the band trails a daily ramp by ≈(1−α)/α ≈ 4 days of increments, so ε ≈ tens of MB/day stays below the threshold **forever** for the pure-EWMA band (~30–60 MB/day ⇒ 5 GB in 3–6 months); the frozen band caps the channel at ≈2 MB/h ⇒ 5 GB ≈ 3 months *and* creates alerts the SOC can escalate on — that friction is the R7 control.

---

## 5. Multivariate detectors and explainability (T4, T5)

**Feature matrix (15 features/account-hour):** 6 context features (robust z vs the account's own usual hour, chained fallback) + 6 `log1p` metrics + circular time (sin/cos hour — 23:00 close to 00:00) + `foreign_country`. `RobustScaler` fitted on train only. LOF (novelty, k=20) and Isolation Forest (200 trees, seed 42), calibrated on validation, FPR = 1 %.

| | dns_tunnel | low_slow | mimicry | brute | AT | night | FPR | alerts/day | P@100 | score 1 day |
|---|---|---|---|---|---|---|---|---|---|---|
| **T4 LOF** | **1.000** | 0.093 | 0.003 | 1.000 | 1.000 | 1.000 | 0.0093 | 108.5 | 0.24 | 0.42 s |
| **T4 iForest** | 0.000 | 0.038 | 0.003 | 1.000 | 1.000 | 0.000 | 0.0082 | 60.4 | 0.06 | 0.033 s |
| ablated LOF (no context) | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.0100 | 50.9 | — | — |
| ablated iForest (no context) | 0.000 | 0.031 | 0.008 | 1.000 | 1.000 | 0.000 | 0.0090 | 65.2 | — | — |

**Q13.** The advisory scenario (`dns_tunnel`: every metric individually usual, the *joint* pattern bent) is caught by LOF (97–100 %) and missed by iForest (0 %): LOF compares local density (a point in a low-density pocket), iForest isolates by random single-axis splits — nothing here is extreme along any axis. **Q14.** Vendor experiment (only mb_out varies): iForest score 0.377 (0.5 GB) → 0.534 (50 GB) → **0.540 (50 GB) = 0.540 (500 GB)** — the score **saturates** because any value beyond the first favourable split is equally easy to isolate; LOF rises monotonically (0.98 → 12.28). The claim "bigger anomalies always get higher scores" is **false**; an insider's 500 GB leak cannot rank above 50 GB — severity is invisible. **Q15.** k=5: hyper-local density, FPR drifts above target, benign alerts rise; k=50: tunnel recall drops, scoring time grows; k=20 chosen at design time on validation only.

**T5 — autoencoder** (MLP 64‑b‑64 relu/adam, trained on train normal rows only; score = mean reconstruction error, calibrated at 1 %):

| bottleneck | dns_tunnel | low_slow | mimicry | AT | night | FPR | alerts/day | P@100 | fit | score 1 day |
|---|---|---|---|---|---|---|---|---|---|---|
| b = 8 | 0.967 | 0.059 | 0.006 | 1.0 | 1.0 | 0.0092 | 69.3 | 0.24 | 8 s | 0.003 s |
| **b = 2** | **1.000** | 0.091 | 0.002 | 1.0 | 1.0 | 0.0071 | 61.4 | **0.37** | 8 s | 0.003 s |

**Q16.** Trained on contaminated data, incidents become part of the manifold the network can rebuild — their errors sink below threshold (same self-masking as T1.2). **Q17.** The narrow bottleneck (b=2) ranks better (P@100 0.37 vs 0.24) and slightly better recall/FPR; the wider one passes more dimensions through — closer to identity, less contrast. **Q18.** Sampled messages, checked against the sealed column:

> **ALERT** — *Account u068 (student) at 31 Oct 04:00 behaves unlike its own usual activity at that hour: its upload volume and machines deviate most (secondary: source IPs). Observed 9 logins / 2 failed / 197.7 MB out / 3 DNS queries.* — ground truth: `account_takeover` ✔
> **ALERT** — *Account u134 (staff) at 18 Oct 02:00 …: upload volume and machines deviate most… Observed 0 logins / 0 failed / 1085.8 MB out.* — ground truth: `backup_job` (benign) — a true alert on a planned change, the exact case the change-log whitelist removes before the SOC sees it ✔
> **ALERT** — *Account u063 (student) at 01 Nov 02:00 …: upload volume and machines deviate most (secondary: source IPs). Observed … 1725.3 MB out / 37 DNS queries.* — ground truth: `night_exfil` ✔

Caveats recorded: only 3/3 sampled alerts verified; mimicry rows cannot get *per-feature* truthful messages (the AE cannot say "jointly unusual"); hour-of-day features are suppressed from messages when uninformative.

---

## 6. Comparison, R1–R7 checklist, recommendation (T6)

All detectors, same rule (validation calibration, target FPR = 1 %), measured once on test. Full table in the notebook (cell "T6 comparison") — headline rows:

| detector | dns_tunnel | low_slow | mimicry | FPR | benign rate | alerts/day | P@100 |
|---|---|---|---|---|---|---|---|
| T1 as-is 3σ (production) | 0.000 | 0.327 | 0.050 | 0.0193 | 0.189 | 134.9 | 0.34 |
| T2 per-account robust | 1.000 | 0.333 | 0.011 | 0.0109 | 0.034 | 75.2 | 0.24 |
| T4 iForest | 0.000 | 0.038 | 0.003 | 0.0082 | 0.118 | 60.4 | 0.06 |
| T4 LOF | 1.000 | 0.093 | 0.003 | 0.0093 | 0.326 | 108.5 | 0.24 |
| T5 autoencoder b=2 | 1.000 | 0.091 | 0.002 | 0.0071 | 0.107 | 61.4 | 0.37 |
| **Portfolio T2(0.5 %)+LOF(0.5 %) union** | 1.000 | 0.238 | 0.005 | 0.0092 | — | 110.9 rows → **45.0 incidents/day** after (account, day) grouping | — |

- **R1** fails as rows for every single detector at FPR = 1 %, and passes after the **grouping rescue** (deduplicate into incidents per account-day): portfolio = **45 incidents/day ≤ 50**. LOF alone groups to 45.9.
- **R2** respected by every calibrated detector (T1 as-is fails at 1.9 %).
- **R3**: portfolio = T2 (typed z messages) + LOF through the T5-style per-feature explainer; as-is and T1 variants explain nothing.
- **R4**: metadata-only everywhere. **R5**: portfolio monitors new accounts from hour one (peer fallback, no personal history needed). **R6**: worst case LOF **0.42 s/day**; AE 0.003 s/day. **R7**: only the T2/frozen-band family resists an informed insider (T4/T5 can be probed against, but their thresholds move with the reviewed baseline updates).

**Q19.** No single best detector: recall-per-type is complementary (LOF owns the tunnel, T2+EWMA owns trajectories and take-overs, the AE owns ranking). **Q20.** High recall with P@100 ≈ 0.2–0.4 means the Monday-100 contains ~2/3 recurring shapes of normal noise clustered on the same extreme-normal accounts — the analyst's felt precision is per *incident*, not per row; the grouping rescue plus whitelist is what makes the queue survivable.

**Still undetected after the debrief:** `mimicry` (0.5 % everywhere) — by design it defeats per-account baselines; non-anomaly controls cover it: per-account allow-lists for lateral-movement patterns, step-up authentication, DNS/egress reputation lists, and canary data marking. `low_slow_exfil` outside upload profile (e.g. split across accounts): cross-account (peer-group) baseline controls.

---

## 7. DPO review (T7) — summary

**Q21** Purpose: detect compromised/misused accounts; processed: hourly security metadata aggregates only — no content, no DPI (Law 09-08); less would not be enough (measured: T1 misses two families and floods the SOC). **Q22** Baselines 8 weeks rolling; raw metadata 13 months; scores/alerts 90 days then counters; access: SOC (alerts), 2 engineers (baselines), DPO on request; none for HR/management. **Q23** Alert → technical triage with typed explanation → change-log suppression only → verification via IT process → escalation only if confirmed; no automated decisions about persons. **Q24** Alerts concentrate on staff/admin at peak (tight baselines), heavy-transfer research staff, and new accounts; mitigated by per-account baselines, hybrid EWMA, whitelists, and a quarterly top-20 fairness review with peer-scale re-estimation.

---

## Limitations stated plainly

Test precision is inflated by the exercise's attack density (Q3); `mimicry` remains effectively undetected and is confessed; the EWMA/α comparison shows week-scale tuning instability that only the frozen band bounds; LOF's benign-event alert rate (0.33 on planned-change rows) depends entirely on the change-log whitelist being up to date — an operational dependency, not a statistical one.

*Companion deliverables: `SENTINEL-U_notebook.ipynb` (reproducible, top-to-bottom, seed 42), `SENTINEL-U_memo_CISO.md` (one-page memo to the CISO).*

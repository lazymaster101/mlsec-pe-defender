# Pitfall audit — the 26 project papers vs. this PE detector

This audits the deployed defender (`rf_augmented`, NFS 250k-hash feature space,
threshold 0.756536) and the dataset/evaluation pipeline against the lessons of the
26 papers in `704papers/`. Every "accounted" verdict points at a concrete artifact;
every "partial"/"gap" verdict says what is missing and whether this audit fixed it.

New measurements produced *by* this audit (so the gaps are numbers, not adjectives):

* `dataset/results/adversarial_featurespace.json` — feature-space evasion under
  functionality-preserving transforms.
* `dataset/results/pitfall_checks.json` — precision at realistic base rates,
  near-duplicate structure, and train/test feature-level leakage.

## Method and honest limits of this audit

* Read the full text of 25 papers; **Fast & Furious** (Ceschin et al., ESWA 2023,
  `S0957417422016463`) was only available as its abstract/landing page — its lessons
  overlap its authors' other papers here (Stream of Problems, Online Binary Models),
  which were read in full, so coverage does not depend on it.
* Verdicts describe *this* artifact. Six papers are the "LLM security" cluster
  (Copilot code security, LLM-assisted RE/repair, LLM-driven attacks, LLM malware
  generation); they shape the **threat landscape** (more, cheaper, novel variants)
  but impose no methodology requirement on the detector. They are marked *context*.
* Two folder papers are adjacent-domain (keystroke-dynamics authentication; machine
  unlearning) and are audited for transferable lessons only.
* Scope note: the folder contains **no** TESSERACT or "packed-goodware" paper, so the
  spatial-bias and packing lessons below are credited only to papers that are present
  (Arp; Transcend/Transcending-Transcend; Humans vs. Machines).

---

## Part 1 — Arp et al., *Dos and Don'ts of ML in Computer Security* (the backbone)

| # | Pitfall | Verdict | Evidence / what this audit found |
|---|---|---|---|
| P1 | Sampling bias | **Partial** | Malware is a real 2020–2026 MalwareBazaar availability sample across 38 families; benign is EMBER-2018 + current Chocolatey PEs (DATASHEET). Two residual biases, now measured: goodware is a 200-PE spot check (not a population), and **~15 % of the recent set is feature-identical to another sample** (repacked variants; `pitfall_checks.json`). Stated, not hidden. |
| P2 | Label inaccuracy | **Partial** | Labels are source-derived: MalwareBazaar = malicious by curation, EMBER/Chocolatey benign = provenance. No independent multi-scanner (VT/AVClass) cross-check was run; `vt_enrich.py` exists but is unused. Threat: a mislabeled feed sample. Called out as an open gap below. |
| P3 | Data snooping | **Partial → improved** | Temporal split is genuinely enforced: EMBER train months < 2018-11, test 2018-11/12 (COMPARISON §3); HashingVectorizer has a *fixed* hash (no vocabulary fit on test → no vocabulary snooping). **But** this audit found **18–19 % of recent-test malware is feature-identical to a training row** (`pitfall_checks.json`): the split isolates SHA-256, not features. Corrected numbers below. |
| P4 | Spurious correlations | **Partial** | Feature space is header/import metadata only — it never sees raw bytes/entropy, so it cannot learn the classic "packed ⇒ malicious" pixel/entropy shortcut. But this audit shows it leans heavily on *import lists and header metadata*, which are trivially forgeable (Part 2). No per-feature attribution (SHAP) was run to rule out other shortcuts. |
| P5 | Biased parameter selection | **Accounted** | The one decisive hyperparameter (`max_features=0.05`) was justified mechanically and its threshold is calibrated on a held-out benign split, not the test set (COMPARISON §4; `package_model.choose_threshold`). No test-set tuning. |
| P6 | Inappropriate baseline | **Accounted** | Compared against the supplied model, a naive-default retrain, a tuned retrain, and the published EMBER GBDT as an industry reference (COMPARISON §2, §6). The naive baseline is kept precisely to show the trap. |
| P7 | Inappropriate measures | **Accounted** | Headline is TPR at the FPR=1 % operating point with Wilson 95 % CIs, plus per-family and per-year slices; accuracy/F1 deliberately omitted (COMPARISON §1). This audit adds precision at realistic base rates (P8). |
| P8 | Base-rate fallacy | **Gap → fixed here** | The report quoted TPR/FPR only. This audit computes PPV across base rates (`pitfall_checks.json`): at a 1 % malware base rate, alerts are **majority false** (PPV 45 % EMBER-derived, 28 % recent-derived); at 0.1 %, mostly noise. So 1 % FPR is *still too high* for a low-base-rate stream. Now stated. |
| P9 | Lab-only evaluation | **Accounted** | Evaluated end-to-end through the real HTTP container under the 1 GB / 5 s budget, fail-toward-detection, live latency percentiles (COMPARISON §8; README). Not just offline scores. |
| P10 | Inappropriate threat model | **Gap → measured, then fixed** | This was the biggest hole: clean-sample metrics with **no** adversarial component, against a model whose exact ancestor was publicly evaded (Part 2). This audit measured functionality-preserving evasion (75 %→9 % on the clean model) **and then hardened the deployed model with adversarial training** (combined attack 7 %→55 % on held-out `recent_test`; COMPARISON §10), while stating the fix's limits (no transfer to untrained mechanism F; ~99 % evaded under full-mimicry D). |

---

## Part 2 — Adversarial robustness (the pitfall the papers care about most)

Papers: **Shallow Security** (ROOTS'19) and the **XOR** paper (ROOTS'20) evade the
*same* "Need For Speed" model family this project deploys, by appending benign
strings/imports and encoding payloads; **GAMMA** (Demetrio, TIFS'21) and **Lucas**
(USENIX'23) show functionality-preserving section/padding attacks collapse comparable
Windows detectors and that adversarial *training* — not plain augmentation — is the
mitigation; **Mal-LSGAN** and **Moving Target Defense** round out attack/defense.
Arp P10 makes an adversarial component mandatory, not optional.

Because the NFS feature space reads only lief-parsed header/import fields, this audit
attacks those fields directly, in memory, on already-extracted attribute dicts — no
malware is decrypted, written, or executed. Each transform edits the attribute dict
the way a functionality-preserving PE rewrite would, then re-scores at the deployed
threshold. (One honest corollary: pure overlay/packer *append* changes **no** NFS
field, so this model is immune to that specific attack — but only because it is blind
to file content; the fields it does read are the forgeable ones.)

Recent malware (2020–2026, full set n≈1454), detection at the deployed threshold:

| Transform (all functionality-preserving) | Detect before | Detect after | Evasion of caught |
|---|---|---|---|
| A — add benign "dead" imports (keep real ones) | 75.2 % | **26.3 %** | 65 % |
| B — rewrite freely-mutable header metadata to a benign file's | 75.2 % | **28.4 %** | 62 % |
| C — A + B combined | 75.2 % | **8.9 %** | 88 % |
| D — full static mimicry of a benign donor (feature-space upper bound) | 75.2 % | **0.9 %** | 99 % |

The held-out set (n=433) behaves the same (66 %→23/28/7/1 %). **Reading:** a trivial,
cheap manipulation — pad the import table with benign API names and copy a benign
file's timestamp/linker/version fields — drops recent-malware detection from 75 % to
**9 %**, i.e. back to the blind level of the un-retrained supplied model. Attack D is
a Pierazzi-style feature-space *upper bound* (may not be fully realizable in problem
space); A/B/C are realizable problem-space edits and are the ones that matter.

**Verdict for P10: measured, then fixed — with the fix's own limits measured too.**
The clean model was *not* adversarially robust. The Lucas remedy (train on the attack)
is **implemented and deployed** as `rf_adv` (realizable attacks A/B/C/E mixed into
training). Evaluated honestly — on the **held-out `recent_test` split** (0 SHA overlap),
with **held-out donors**, at the **deployed threshold**, with Wilson CIs — the trained
attacks are far harder: combined attack C **7 % → 55 %** (CIs [5-10] vs [51-60],
non-overlapping) and packing E **21 % → 76 %**. Two honest limits, from the same table:
(1) an *untrained* realizable mechanism, section-injection (F), does **not** improve
(59 % → 58 %) — no transfer to unseen mechanisms; (2) the full feature-mimicry upper
bound (D) leaves both models ~99 % evaded. Clean cost: 2.8 pt EMBER TPR, ~7.6 pt
held-out recent. So this is in-distribution robustness to the trained attack families
on held-out samples — real and worth deploying, not a claim of general robustness. Full
method and CIs in COMPARISON_REPORT §10; `dataset/results/adversarial_training.json`.

*(Self-correction, this audit's own dogfood: the first adversarial eval attacked the
full recent set, 70 % of which is training data — the very P3 snooping pitfall. A
follow-up multi-agent audit caught it; the numbers above are the corrected held-out
figures. The contaminated first pass had read ~9 pt higher.)*

---

## Part 3 — Concept drift and temporal evaluation

Papers: **Ceschin — Stream of Problems**, **Fast & Furious** (abstract), **Transcend**
(Jordaney, USENIX'17), **Transcending Transcend** (S&P'22), **DroidEvolver**,
**Online Binary Models** (Giovanini/Ceschin, T-BIOM'22).

| Lesson | Verdict | Evidence |
|---|---|---|
| Temporal ordering / no time-travel leakage | **Accounted** | EMBER split by month; recent set is post-2020 (COMPARISON §3, §5). |
| Drift is real and large | **Accounted (headline result)** | AUC 0.976 → 0.79 on recent malware; whole 2023–26 families missed by the static model; retraining lifts recent detection 9 %→75 % (COMPARISON §5, §7). |
| Feature-extractor drift (not just classifier) | **Accounted by construction** | HashingVectorizer is a fixed hash with no fitted vocabulary, so the extractor cannot drift the way a TF-IDF/Word2Vec vocabulary does (the Fast & Furious concern). |
| Rejection / "classify with confidence" under drift | **Gap (design choice)** | Transcend's conformal rejection is not implemented; the deployment answers every sample (the challenge forbids abstaining). Noted as a deliberate constraint, not an oversight. |
| Self-training/pseudo-labels can self-poison | **Accounted (avoided)** | DroidEvolver's known failure mode is why retraining here uses source-verified labels on a schedule, not model-generated pseudo-labels. |
| Delayed labels | **Partial** | Acknowledged in the threat model; not simulated with a label-delay buffer. |

---

## Part 4 — Poisoning, backdoors, and the training feed

Papers: **Lookin' Out My Backdoor** (D'Onghia, AISec'23), **TrojanPuzzle**,
**Machine Unlearning** (mitigation).

* **Relevant because training pulls from a public feed (MalwareBazaar).** A poisoned
  or mislabeled feed sample is a real vector (D'Onghia targets exactly ML PE
  detectors). **Verdict: partial.** Mitigations in place: source curation, exact-hash
  dedup, temporal/family separation. **Missing:** no multi-scanner label cross-check
  (ties to P2) and no poisoning-canary check. Machine Unlearning is noted as the
  remediation path if a poisoned batch is later identified. Logged as an open gap.

---

## Part 5 — Features, spurious signal, and human comparison

* **Humans vs. Machines** (Aonzo, USENIX'23): ML leans on static header/resource
  features that analysts consider weak and that are easy to forge. **Confirmed
  directly here** — Part 2 shows import/header features carry most of the decision and
  fold under trivial edits. **Verdict: accounted (as a measured weakness).**
* **DeepSign**, **AutoYara** (signature/rule generation): context for "an ML model is
  just a smarter signature." Reinforces that a static model needs scheduled retraining
  (Part 3); no direct requirement on this pipeline. *Context.*

---

## Part 6 — Corrected numbers (from the leakage found in P3)

The recent-test headline (98.8 % TPR @ 0.25) is **saturated and misleading**: at 0.25
the benign FPR on that set is 48 %, so 0.25 is not an operating point. At the deployed
threshold, separating leaked from novel test rows (`pitfall_checks.json`):

| Recent-test malware | n | TPR @ deployed 0.756 |
|---|---|---|
| all | 433 | 66.3 % |
| feature-identical to a train row (leaked) | 84 | 90.5 % |
| **novel features (honest generalization)** | 349 | **60.5 %** |

So the true "new instance of a known family" detection at the deployed threshold is
~**60 %**, not 66–99 %. The augmentation result (drift §7) still stands — the full-set
9 %→75 % gain is measured over the whole recent set and the clean EMBER-temporal gain
is leakage-free — but the held-out figure was inflated and is now corrected.

---

## Part 7 — Gap ledger (what remains, ranked)

| Gap | Pitfall | Status |
|---|---|---|
| No adversarial robustness | P10; Shallow/XOR/GAMMA/Lucas | **Measured, then FIXED (held-out).** Deployed `rf_adv` (COMPARISON §10): combined attack 7 %→55 %, packing 21 %→76 % on held-out `recent_test`. Limits stated: no transfer to untrained mechanism F, ~99 % evaded under full-mimicry D. |
| Train/test feature-level leakage (~18 %) | P3 | **Measured & corrected** (Part 6). Fix = dedup by feature-fingerprint before splitting. |
| Base-rate precision not reported | P8 | **Fixed** (Part 2/`pitfall_checks.json`). |
| No independent label cross-check | P2 | **Open.** Run `vt_enrich.py` / AVClass on the feed. |
| Feed-poisoning defense | D'Onghia/TrojanPuzzle | **Open.** Canary + unlearning path. |
| Goodware is a spot check, not a population | P1 | **Stated**, unchanged (large-sample FPR uses EMBER 100k benign). |
| No conformal rejection | Transcend | **By design** (deployment cannot abstain). |

**Bottom line.** The strong pitfalls — temporal evaluation (P3 core), proper measures
and CIs (P7), baselines (P6), calibration/threshold hygiene (P5), real-container
evaluation (P9), and drift as the headline (Parts 3) — are genuinely accounted for.
This audit closed three that were open: base rate P8; leakage-corrected numbers P3;
and the mandatory adversarial component P10 — first measured (the clean model *was*
evadable, 75 %→9 %) and then **fixed by deploying an adversarially-trained model**
(`rf_adv`, combined attack 7 %→55 % on held-out malware; COMPARISON §10), with the
fix's own limits (no transfer to untrained mechanisms; full mimicry still wins) stated.
The remaining open
items (independent labels P2, feed-poisoning defense) are named honestly rather than
claimed.

---

## Appendix — the 26 papers and how each is handled

**Methodology backbone**
1. Arp — *Dos and Don'ts of ML in Computer Security* → Part 1 (all 10 pitfalls).

**Concept drift / temporal evaluation**
2. Ceschin — *Machine Learning (In)Security: A Stream of Problems* → Part 3.
3. Ceschin — *Fast & Furious* (abstract only) → Part 3 (extractor drift).
4. Jordaney — *Transcend* → Part 3 (rejection: design gap).
5. Barbero — *Transcending Transcend* → Part 3.
6. Xu — *DroidEvolver* → Part 3 (self-poisoning avoided).
7. Giovanini/Ceschin — *Online Binary Models…* → Part 3 (online drift).

**Adversarial evasion / defense**
8. Ceschin/Botacin — *Shallow Security* (evades NFS) → Part 2.
9. Botacin — *No Need to Teach New Tricks… (XOR)* (evades NFS) → Part 2.
10. Demetrio — *GAMMA: Functionality-Preserving Black-Box…* → Part 2.
11. Lucas — *Adversarial training for malware classifiers* → Part 2 (the fix).
12. *Mal-LSGAN* → Part 2 (GAN variant generation).
13. *Moving Target Defense Against Adversarial ML* → Part 2 (defense option).

**Features / human comparison**
14. Aonzo — *Humans vs. Machines in Malware Classification* → Part 5 (confirmed).

**Poisoning / backdoor / remediation**
15. D'Onghia — *Lookin' Out My Backdoor!* → Part 4.
16. Aghakhani — *TrojanPuzzle* → Part 4.
17. Bourtoule — *Machine Unlearning* → Part 4 (remediation path).

**Signature / rule generation (context)**
18. *DeepSign* → Part 5 (context).
19. *AutoYara (biclustering)* → Part 5 (context).

**LLM-security cluster (threat-landscape context; no methodology requirement)**
20. *GPThreats-3: Automatic Malware Generation* — cheaper novel variants → motivates Parts 2–3.
21. *AutoAttacker (LLM-guided attacks)* — same.
22. *Asleep at the Keyboard? (Copilot security)* — context.
23. *Examining Zero-Shot Vulnerability Repair with LLMs* — context.
24. *Pop Quiz! Can an LLM Help With Reverse Engineering?* — context.
25. *Lost at C (LLM code-assistant security)* — context.

**Adjacent-domain (transferable lessons only)**
26. Bhana & Flowerday — *Passphrase and keystroke-dynamics authentication* — behavioral-biometrics evaluation; drift lessons transfer, not malware-specific.

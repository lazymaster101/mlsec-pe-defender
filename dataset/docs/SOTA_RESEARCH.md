# State of the art for static PE malware detection — research & roadmap

A literature review (2018–2026) beyond the 26 course papers, to push our detector
toward the best *achievable* design. Produced by a multi-agent web-research pass whose
**load-bearing SOTA numbers were verified against primary sources**; where verification
flagged a widely-cited number as overstated, it is marked *[caveat]*.

## 0. The honest reframe (why "one model, always detect" is the wrong target)

A universal, always-detect static PE classifier is not merely hard — it is ruled out by
four independent walls, each now citation-grounded:

1. **Undecidability.** Deciding whether an arbitrary program is malicious reduces to
   undecidable problems (Cohen 1987; Rice's theorem). No static procedure is complete.
2. **Adversarial evasion.** Black-box, functionality-preserving attacks evade static
   detectors at will — MAB-Malware **74–97 %** vs two SOTA ML detectors and 32–48 % vs
   commercial AV; GAMMA evades EMBER-GBDT *[caveat: the often-quoted "69 %" is
   configuration-specific — verify conditions]*. Certified defenses bound only tiny
   contiguous byte edits (see §5).
3. **Concept drift.** Under honest temporal evaluation the *same* SOTA model collapses:
   LAMDA LightGBM **F1 97.5 % (IID) → 47–59 % (temporal)**; Android detectors lose ~50 %
   F1 over 48 months (TESSERACT). "Detect future/zero-day reliably from static features"
   is unsupported.
4. **Base rate.** At realistic prevalence (~1 % malware), even 99 % TPR / 1 % FPR gives
   ~50 % precision; ~40 % precision at real prevalence needs **FPR ≈ 1e-6**. Vendors
   operate at FPR 1e-4…1e-6 and never on a single static model.

**The evidence-backed target is therefore:** a **low-FPR, drift-adaptive detector that
is one stratum of a defense-in-depth stack** — which is exactly what won the MLSEC
defender challenge (a *diversified* ensemble of ML + stateful/signature + monotonic
checks beat every single robust model). We optimize for that, and we characterize the
ceiling honestly rather than claiming to beat it.

*Verification note: TESSERACT, LAMDA, MAB-Malware, Arp P8, and the MLSEC outcome were
confirmed against primary sources; treat the four walls as well-established.*

---

## 1. Datasets — move beyond EMBER-2018 + MalwareBazaar

| Dataset | Scale / period | Why it matters | Verified? |
|---|---|---|---|
| **EMBER2024** | 3.24 M files, Sep 2023–Dec 2024, PE-dominant; built-in 52-wk train / 12-wk test split; 6,315-file **AV-evading challenge set**; family/behavior/packer/CVE/threat-group labels | The modern base for representative + temporal + robustness eval | ✅ all headline counts verified |
| **SOREL-20M** | ~20 M PE, 2017–2019; EMBER-v2 features; **9.9 M disarmed malicious binaries** | Best source of *raw* malicious PE at scale (re-extractable into any feature space) | ✅ counts verified |
| **BODMAS** | 57 k mal + 77 k benign PE, 2019–2020; 581 families; per-sample first-seen timestamp | Cleanest small drift/family testbed; disarmed malware binaries provided | ✅ verified |
| **MOTIF** | 3,095 PE, 454 families, **report-validated ground-truth labels** | Label-quality audit / family test set (not AV-heuristic) | reported |
| **RawMal-TF adversarial** (2026) | 44 k + 34 k **real functionality-preserving evasive PE** (GAMMA/MAB/AMG/Pesidious) + poisoning protocol | Honest adversarial + poisoning evaluation | reported (recent preprint) |
| **PRISM** (2026) | 83 k section-aware matrices incl. 2024–2025 malware | Contemporary-drift eval, EMBER-compatible | ✅ paper verified |

**Two hard constraints the research surfaced:**
- **Benign-binary gap.** *None* of SOREL/BODMAS/EMBER2024 redistribute benign binaries
  (copyright). To re-extract our own feature space we must assemble a clean corpus
  (Chocolatey/winget/**NSRL**) — exactly the goodware sourcing we already started.
- **Temporal split is non-negotiable.** Random splits leak future families and inflate
  numbers by large margins. Use real *first-seen* timestamps (not spoofable compile
  time — "Breaking Out from the TESSERACT", arXiv 2506.23814).

**Recommendation:** train on **EMBER2024** (its official temporal split) for the rich
feature model; keep MalwareBazaar as the live-current feed; evaluate drift on BODMAS +
a 2025–2026 slice; evaluate robustness on the EMBER2024 challenge set + RawMal-TF; use
MOTIF to audit label quality.

---

## 2. Features & models — the single highest-impact upgrade

**Finding (converges across 3 dimensions):** hand-crafted **EMBER-style 2381-dim
features fed to a gradient-boosted tree (LightGBM)** is the reigning
*accuracy-per-constraint* representation, and **GBDT beats RandomForest** in this space.

- EMBER-2018 LightGBM: **ROC-AUC ≈ 0.9991, ~98 % TPR@1%FPR, ~93 % TPR@0.1%FPR** on the
  200 k test split *[caveat: verification flagged the exact numbers as
  condition-specific — EMBER's own README notes the model isn't heavily tuned; treat as
  "~0.999 AUC / high-90s TPR@1%FPR IID," not a precise guarantee]*.
- EMBER2024 LightGBM: **94.48 % TPR@1%FPR on the *temporal* test set** (✅ verified) —
  materially lower on the challenge set.
- SOREL-20M baselines (LightGBM + ALOHA multi-task NN): ~0.998 AUC, TPR@0.1%FPR > 90 %;
  low-FPR-focused work reports **0.956 (EMBER) / 0.965 (SOREL) TPR@0.1%FPR**.
- Cost: LightGBM is **< 10 MB, millisecond CPU inference** → fits our 1 GB / 5 s budget
  with room to spare.

Other representations, honestly:
- **PRISM** 425-dim section matrix nearly matches EMBER (AUC 0.9994) at ~1/6 the size —
  cheap structural add-on (✅ verified).
- **Raw-byte CNNs (MalConv/MalConv2)** underperform GBDT on clean accuracy *and* are
  adversarially fragile (append/slack attacks drop MalConv from >90 % to <2 %). Not our
  path.
- **FCG-GNNs and byte/disassembly transformers** are the credible "approach-the-ideal"
  directions (capture semantics byte/tabular models miss) but need disassembly + graph
  inference and don't yet fit a ≤1 GB / ≤5 s static budget.

**Recommendation (ceiling-breaker):** our NFS 250k-hash space structurally caps at
~80 % TPR@1%FPR. **Adopt EMBER's 2381 rich features + a GBDT (LightGBM/XGBoost).** Our
earlier GBDT rejection was specific to the 250k-*hash* space (histogram cost); on 2381
dense features GBDT is cheap and is the documented SOTA. Our sklearn-free runtime
*already* supports a `gbdt_logistic` ensemble, so the runtime change is small.

---

## 3. Adversarial robustness — what actually holds

**Attacks dominate static detectors.** GAMMA (genetic, section-injection + padding),
MAB-Malware (RL bandit), and GAN generators evade at 40–97 %. The evadable surface is
attacker-*addable* content: padding, new sections, slack, DOS header.

**Certified defenses exist but bound only tiny, contiguous byte edits:**
- **RS-Del** (edit-distance certificate): median certified radius **6–688 bytes** on
  multi-MB files (✅ verified) — orders of magnitude below real attack budgets.
- **DRSM** (ICLR'24, de-randomized smoothing): clean ~98 %, certified **~54 % @ Δ=2
  windows**.
- **CS-MalConv** (chunk smoothing): strongest byte defense, **88–95 % certified vs
  5–20 % patches**, ~0.05 s/example.
- All three are **raw-byte MalConv** defenses — **not transplantable to a feature-space
  tree**.

**The defense that fits us: design-level monotonicity + a reject-option stage.**
- **ERDALT** (Certifiably Robust Malware Detectors by Design, IFIP-SEC 2025, arXiv
  2508.10038): a linear post-processing layer enforcing **monotonicity on
  attacker-additive EMBER features** → **93 % AUC / 96 % robust** vs an 8-attack suite.
  Because attackers can usually only *add* features, a monotone/non-negative model is
  robust-by-construction to feature-addition. Two qualifiers (review 2026-09-21): the
  93/96 figures are the paper's *empirical* ERDALT method; its *certified* construction
  is a separate result (§4 of the paper). And the NFS space is not coordinatewise
  monotone under token addition — signed hashing plus L2 normalisation can move any
  coordinate either way — so a monotone constraint on this pipeline would not be a
  certificate.
- **EXE-scanner** (arXiv 2405.02646): a decoupled reject-option / adversarial-example
  detector *layered on top* achieves ~0 clean flips at 1 % FPR, and — critically —
  **naive adversarial training "induces regression + drift damage."** This independently
  confirms the exact clean-cost we measured when we adversarially trained `rf_adv`.

**Recommendation:** don't chase byte-level certificates for our tree. Instead: (a)
enforce **monotone constraints** on attacker-additive features (import/section counts,
appended-content-derived), (b) add a **decoupled reject-option** stage rather than only
mixing adversarial samples into training, and (c) benchmark against **GAMMA + MAB** via
`secml-malware` at fixed FPR. Our adversarial training stays as one layer, but monotone
design is the higher-leverage, lower-clean-cost robustness lever.

---

## 4. Concept drift — how to stay current (the real "keep detecting")

The methodology is settled: **TESSERACT** constraints (C1 train-before-test, C2
time-consistent windows, C3 realistic ~10 % malware) + **AUT** (Area Under Time) of
recall at fixed low FPR as the headline metric.

- **Label-efficient AL+SSL** (arXiv 2603.28396) — validated on *our exact stack*
  (RandomForest + EMBER Windows PE, monthly batches): recovers most of the full-relabel
  F1 gap at a **2 % monthly labeling budget** (no-retrain F1 66 → full-relabel 91 →
  BADGE-AL@2 % ≈ 82) (✅ verified). These are F1 numbers from that paper's RF + EMBER
  setup, not TPR/FPR on this product; "our exact stack" means the same model family and
  feature set, not this detector.
- **SEED** (semi-supervised continual, ACM TOPS 2026): **+32 % unseen-task AUT on BODMAS
  Windows PE** at 100 labels/month (✅ verified).
- **TRANSCENDENT** conformal rejection (USENIX'22): per-class p-values quarantine
  low-credibility drifted samples for analyst review instead of forcing a decision.
- **Drift-triggered** retraining (MMD/OCSVM on the monthly batch) cuts retraining cost
  ~58 % vs always-retrain.

**Recommendation:** make **AUT@1%FPR** the headline; add a **conformal-rejection band**;
drive monthly retraining with **AL+SSL** at a small labeling budget; trigger on measured
drift. This is the part that most determines real-world lifespan.

---

## 5. Packing — the dominant confound

Aghakhani et al., **"When Malware is Packin' Heat"** (NDSS'20): packed executables
preserve *some* classifiable signal, but it **does not capture behavior**, and static
features **cannot generalize to unseen packers or resist adversarial examples**.
Packed-goodware vs packed-malware is the classic P4 spurious correlation.

- **For us specifically:** our import/header features *partially survive* packing —
  the unpacker stub's imports and header remain visible — so we degrade more gracefully
  than an entropy/section-only model, but we inherit the "no generalization to unseen
  packers" limit.
- Tooling: EMBER2024 ships **52 packer tags**; DIE/Detect-It-Easy and PackHero (arXiv
  2506.00659) identify packers; generic dynamic unpacking exists but rarely fits a ≤5 s
  static budget.

**Recommendation:** don't unpack inline (breaks the budget). Instead **stratify
reporting by packer tag** (TPR on packed vs unpacked) so aggregate numbers don't hide
packed evasion, and **avoid entropy-only cues** as a primary signal (Aghakhani's warning
+ our own P4 audit).

---

## 6. Evaluation & the production bar

- **Report the operating curve, never one number:** TPR at **FPR = 1 %, 0.1 %, 0.01 %**,
  plus **precision at a stated realistic base rate**, plus **AUT over time**. (We already
  do TPR@1%FPR + Wilson CIs; add 0.1 %/0.01 % and AUT.)
- **MLSEC reality:** no single static model was robust; the **diversified ensemble won**.
- **Production bar:** AV-Comparatives real-world 2025 shows full multi-layer stacks at
  **94–100 % block, single-digit FPs** — a level static-only ML cannot reach alone.

---

## 7. Prioritized upgrade roadmap for *our* detector

Ranked by impact-per-effort, all within the 1 GB / 5 s static budget:

1. **Break the ceiling — EMBER-2381 features + LightGBM/XGBoost GBDT.** Biggest single
   jump (our ~80 % → high-80s/90s TPR@1%FPR IID; ~94 % is the EMBER2024 temporal SOTA).
   Runtime already supports `gbdt_logistic`. *High impact, medium effort.*
2. **Upgrade the data — EMBER2024 temporal split** (+ BODMAS for drift, MOTIF for label
   audit, RawMal-TF for adversarial eval). *High impact, medium effort.*
3. **Robustness by design — monotone constraints (ERDALT's empirical pattern; not a
   certificate in this feature space, see above) + a reject-option stage**, replacing
   reliance on clean-cost-heavy augmentation. *High impact, medium effort.*
4. **Drift pipeline — AUT@fixed-FPR metric + conformal rejection + AL/SSL monthly
   retraining** at a 2 % labeling budget. *High impact on lifespan, medium effort.*
5. **Report at FPR 1 %/0.1 %/0.01 % + precision at base rate**, stratified by packer tag.
   *Low effort, high honesty.*
6. **Frame as defense-in-depth** — position our model as one stratum; note where dynamic
   / reputation / allowlisting layers belong. *Low effort.*

**Expected honest outcome:** a detector that reaches roughly the EMBER2024 temporal SOTA
(~90–94 % TPR@1%FPR on *held-out future* data), is robust-by-design to cheap additive
evasion, and stays current via cheap retraining — while still being one layer of a
stack, not a universal oracle. That is the excellence that is actually reachable.

---

## References (verified primary sources)

- EMBER2024 — arXiv 2506.05074
- EMBER-2018 (LightGBM baseline) — arXiv 1804.04637
- SOREL-20M — arXiv 2012.07634 · github.com/sophos/SOREL-20M
- BODMAS — whyisyoung.github.io/BODMAS
- MOTIF — github.com/boozallen/MOTIF
- PRISM — arXiv 2606.27109
- RawMal-TF adversarial dataset — arXiv 2605.25937
- ERDALT (monotone certified-by-design) — arXiv 2508.10038
- DRSM — arXiv 2303.13372 · CS-MalConv — arXiv 2405.00392 · RS-Del — arXiv 2302.01757
- EXE-scanner / "Updating Windows Malware Detectors" — arXiv 2405.02646
- Label-efficient AL+SSL updates — arXiv 2603.28396 · SEED — arXiv 2605.24903
- TRANSCENDENT — arXiv 2010.03856 · TESSERACT (extended) — arXiv 2402.01359
- LAMDA (longitudinal drift) — arXiv 2505.18551 · Breaking Out from TESSERACT — arXiv 2506.23814
- Aghakhani, "When Malware is Packin' Heat" (NDSS'20) — seclab.cs.ucsb.edu · PackHero — arXiv 2506.00659
- Arp et al., "Dos and Don'ts of ML in Computer Security" (USENIX Sec'22)

*Recency caveat: several 2026 arXiv preprints (RawMal-TF, PRISM, AL+SSL, SEED) are very
recent; the verification pass confirmed the ones marked ✅ in §1–§4 against their primary
source, and the rest are cited as reported — confirm before relying on exact figures.*

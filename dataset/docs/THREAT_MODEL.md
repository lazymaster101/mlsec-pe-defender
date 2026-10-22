# Threat model and dataset design

This fixes what the detector is defending against, because that choice determines
how the dataset is built and which numbers are meaningful. Written against the
delivered artifact: a **static** Windows PE classifier behind HTTP, judged at
FPR ≤ 1 %, TPR ≥ 95 %, ≤ 1 GB RAM, ≤ 5 s per sample.

## 1. Asset and adversary goal

The asset is the verdict. The adversary wants a **false negative**: a binary that
retains its malicious behaviour and is returned `0`. Inducing false positives is a
secondary nuisance goal and is covered by the FPR budget, not treated as the
primary attack.

## 2. Adversary knowledge — assume white-box on the shipped model

The MLSEC grading interface gives an attacker **black-box query access**: submit a
sample, observe `0` or `1`, with no score. That is the *minimum* assumption.

The realistic assumption is stronger. The NFS architecture, its training code, and
`NFS_21_ALL_hash_50000_WITH_MLSEC20.pkl` itself are **publicly distributed**. An
adversary can hold the exact weights being served. The detector therefore gets no
credit for obscurity, and any defence that depends on the attacker not knowing the
feature layout is void. Concretely: the hashed-text blocks, the 0.25 threshold, and
which 22 numeric header fields are read are all attacker-known.

*Consequence for the dataset:* a retrained model is worth more than a tuned
threshold on the public one, because retraining is the only step that moves the
decision boundary away from what the attacker already holds.

## 3. Adversary capability — functionality-preserving transformation

The attacker edits the binary but must keep it running; MLSEC validated this by
detonating candidates in a sandbox. The capability set, ordered by cost:

| Class | Transformation | Which features it moves |
|---|---|---|
| Append | overlay padding, benign-content append | `virtual_size`, nothing else structural |
| Section | add/rename sections, inject benign content | `numberof_sections`, `sizeof_code` |
| Header | timestamp, version fields, checksum, DLL characteristics | 22 numeric fields, `dll_characteristics_list` |
| Import | add unused imports, reorder, ordinal↔name | `imports`, both hashed import blocks |
| Packing | UPX and commodity packers | nearly all of them at once |
| Signing | append a certificate blob | `has_signature` |

Out of the attacker's reach for a static detector of this design: changing observed
runtime behaviour without changing the file, and anything requiring the defender to
execute the sample.

## 4. Explicitly out of scope

Stating these prevents scope creep and stops unrelated results being cited as
evidence:

* **Training-set poisoning and backdoors.** The image ships immutable, hash-pinned
  weights and never learns from request traffic. The backdoor literature is
  therefore about a supply chain we do not have.
* **Model extraction.** The weights are already public; there is nothing to steal.
* **Service-level DoS.** Handled as engineering (body caps, worker bounds, a
  latency budget that answers `1` rather than overrunning), not as a modelled
  adversary.
* **Dynamic/behavioural evasion.** We are a static detector by construction.

## 5. The second adversary: time

Most TPR loss in deployment is not an attacker — it is **concept drift**. New
families and repacked campaigns appear after training. This is not optional to
model: it is the dominant failure mode, and a random train/test split hides it
completely by letting tomorrow's samples leak into training.

## 6. What the dataset must therefore provide

Derived directly from §2–§5, each with the failure it prevents:

1. **Temporal split on first-seen date.** Train strictly before a cutoff, test
   strictly after. Prevents the single largest source of inflated results.
2. **Realistic evaluation base rate.** Training may be balanced; FPR must be read
   off a benign-heavy set, because a 50/50 test set makes a 1 % FPR look far
   cheaper than it is on real endpoint traffic.
3. **Family and type diversity.** Per-family slices, so one over-represented family
   cannot carry the headline TPR.
4. **Deduplication.** Exact-hash at minimum; near-duplicates across the split
   boundary otherwise re-measure training data.
5. **Packed samples in both classes.** Packed *goodware* (installers) especially —
   without it the model learns "packed ⇒ malicious", which is both wrong and a
   one-step evasion in reverse.
6. **Label provenance.** Labels derived from AV consensus with an explicit rule and
   an explicit discarded middle band, not a single vendor's verdict.
7. **Adversarial variants held out.** Synthetic feature-space perturbations modelled
   on the §3 transforms, applied to test rows and scored separately. Clean-set TPR
   alone does not describe §2–§3. **Delivered** as an in-memory feature-space probe
   (append benign dead imports; rewrite mutable header metadata; no PE produced or
   executed) — see
   [PITFALL_AUDIT.md](PITFALL_AUDIT.md) Part 2 and
   `dataset/results/adversarial_featurespace.json`.

## 7. How success is measured

The headline number is **TPR at FPR = 1 %**, on the temporal test set, not accuracy
and not AUC. Accuracy is meaningless at realistic base rates; AUC averages over
operating points we will never run at. Reported alongside it:

* TPR at the 1 % FPR operating point, with a confidence interval
* per-family and per-month slices
* TPR on adversarially transformed malware rows (feature-space perturbations) — **measured: 75 % → 9 %** on the clean
  model under a cheap combined transform, **hardened to 55 % on held-out malware by the
  deployed adversarially-trained `rf_adv`** (COMPARISON_REPORT §10), with the fix's
  limits (no transfer to an untrained mechanism; full mimicry still evades) reported
* precision at realistic base rates (base-rate fallacy), since 1 % FPR is still high
  for a low-base-rate stream (`dataset/results/pitfall_checks.json`)
* extraction + inference latency and resident memory, which are part of the
  detector, not footnotes

## 8. Honest limits of this threat model

A static feature model of this shape cannot be made robust to a determined
white-box attacker with unlimited functionality-preserving edits; GAMMA
demonstrates detection collapsing under section injection against comparable EMBER
GBDT models. The realistic aim is to raise attack cost and to hold the clean and
drifted TPR, not to claim adversarial robustness. Any robustness number here
describes the specific transforms tested and nothing beyond them.

This is now quantified rather than asserted: the measured collapse on the clean model
is 75 % → 9 % under a combined append-imports + header-rewrite transform, and to 0.9 %
under full feature-space mimicry (an upper bound). The remedy implemented is random
augmentation with these same perturbations (`rf_adv`). That is the unguided augmentation
which Lucas et al. (USENIX'23) show to be weaker than attack-based training on real
binaries; it is not that method, and an earlier version of this paragraph said otherwise.
On held-out rows it holds the trained combined perturbation at 55 % (from 7 %) and packing
at 76 % (from 21 %), for a 2.8-point clean-TPR cost. It does **not** claim robustness
beyond the trained perturbations: an untrained mechanism (section-injection, F) shows no
gain, and the full-mimicry upper bound (D) still evades ~99 %. All of this is feature
space: no adversarial binary was produced, validated or executed. It raises the cost of
the cheap perturbations; it is not general robustness. See
[COMPARISON_REPORT.md](COMPARISON_REPORT.md) §10 and
[PITFALL_AUDIT.md](PITFALL_AUDIT.md) Parts 2 and 7.

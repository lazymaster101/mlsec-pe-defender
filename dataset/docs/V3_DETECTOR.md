# v3 detector: what changed, why, and what the numbers honestly mean

Date: 2026-10-15. Code: `defender_product/defender/{ensemble,trust,features}.py`,
artifacts `defender_product/models/{ember_ft/ember_ft.txt,fusion.json}`, training
`dataset/tools/train_v3.py`. Concept-by-concept mapping of all 26 course papers:
`dataset/docs/PAPER_CONCEPTS.md`.

## 1. Decision pipeline

1. **Authenticode trust.** The file is benign if its signature is intact (LIEF
   `verify_signature() == OK`). The signer certificate must be cryptographically signed
   by one of five pinned Microsoft first-party code-signing PCAs; the RSA check is done
   in pure Python, not by comparing subject strings. No bytes may follow the signature
   (CVE-2013-3900). Third-party and hardware-compatibility Microsoft CAs are deliberately
   **not** pinned. Results: 0/1,455 malware trusted, 2,120/2,137 Microsoft-signed corpus
   files trusted. Every forgery test fails as it should (appended payload, flipped code
   byte, edited certificate, third-party leaf).
2. **Tampered signature.** A signature that is present but broken (BAD_DIGEST,
   CERT_NOT_FOUND or INVALID_SIGNER) makes the file malicious. This occurs in 95/1,455
   malware and 0/11,385 goodware.
3. **ML fusion.** Logistic regression on the log-odds of three members:
   `e` = ember_gbdt (EMBER-2381, trained on EMBER 2018), `r` = rf_adv (NFS,
   recent + adversarial), and `f` = ember_gbdt + `ember_ft` (continued boosting on
   live-extracted recent malware and goodware, class-balanced inside each
   DLL/EXE × .NET/native stratum).
   - The fusion is fitted on out-of-fold scores.
   - If one extractor fails, a dedicated fallback fusion (`ef` or `r`) takes over.
   - Only input that **no** extractor can read is flagged.

## 2. Bugs and gaps found along the way

| Finding | Effect on v2 | Fix |
|---|---|---|
| `features.py` called `.name` on LIEF ints (.NET ReadyToRun machine codes), which crashed, so fail-toward-detection set r=1.0 | **15.8% FPR** on 5,788 independent goodware; 26 corpus FPs | `_enum_name` maps the OS-XOR'd machine back to the real architecture; regression tests added |
| v2's "<1% FPR" was dominated by easy .NET DLLs | goodware **EXE** FPR 3.4% (17/500), 3.9% for non-Microsoft EXEs | the threshold is now constrained on the EXE stratum as well |
| v2's threshold (1.80) had been chosen on the grading set | 48/50 there was a post-selection number | the v3 threshold is set on our data only; the grading set was run once, after freezing |
| `lief.PE.parse(list(bytez))` | slow, with a large transient RAM spike on big files | `parse(bytes)`; features bit-identical on 220/220 samples |

## 3. Results (grading set excluded unless stated)

Protocol: malware folds are grouped by **family** and goodware folds by **package/origin**,
following Arp et al. 2022 and TESSERACT. Feature-identical near-duplicates are removed.
The threshold is set on training folds, requiring FPR ≤ 0.75% on all goodware **and** on
EXE goodware. Reported figures are the mean of 10×5-fold CV
(`fusion.json["cv_estimate"]`).

| On the same held-out set | Malware TPR | FPR, all goodware | FPR, goodware EXEs |
|---|---|---|---|
| v2 as shipped (t=1.80, crash fixed) | 81.4% | 0.20% | **3.4%** |
| v3 | **83.5% ± 4.1** (EXE malware 85.1%) | **0.10%** | **1.1% ± 1.5** |

At matched EXE FPR (~1%), the v2 linear fusion reached about 72%, so v3 is about +11 points.

**Robustness.** In-memory problem-space variants of 349 held-out malware (`eval_robustness.py`).
v3 is at least as good as v2 on every attack:

| Attack | v3 | v2 |
|---|---|---|
| none | 87.7% | 81.4% |
| 4 MB benign overlay | 80.2% | 76.5% |
| 10k goodware strings | 81.1% | 78.2% |
| benign section injected | 86.2% | 81.7% |
| header metadata copied | 92.0% | 85.1% |
| real signature blob appended | 89.1% | 79.9% |

These absolute numbers are optimistic for v3 because `ember_ft` saw these malware rows.
The v3-versus-v2 comparison on the same rows is the meaningful part.

**Course grading set.** One run on the frozen container (offline, 1 CPU, 1 GiB, read-only):
**48/50 TP, 0/50 FP, PASS**. Latency p95 was 56 ms (v2: 102 ms), memory 188 MiB, ready in 3 s.
A 33 MB file took 1.43 s on 1 CPU (budget 4 s). The two misses score 3.27 and 3.07
against a 4.11 threshold. They were deliberately **not** tuned for, because doing so would
be test-set fitting.

## 4. What cannot be claimed

- **100% TPR.** No static detector can promise 100% TPR on families it has never seen:
  "an ML model is a type of signature" (Ceschin et al.). The published state of the art
  on temporal splits is about 94–95% TPR at 1% FPR. Even a perfect 50/50 on a 50-sample
  set has a Wilson 95% lower bound of only 92.9%.
- **Optimistic member scores.** `ember_ft` was trained on all live data, including the
  local goodware, so end-to-end scores on those rows are in-sample. The honest numbers
  are the grouped-CV ones above.
- **Small EXE sample.** EXE goodware is the binding constraint. Its estimate rests on
  about 430–590 files, so the per-fold spread (±1.5%) is wide.

## 5. Next steps, ranked by expected value

1. **Grow native-EXE goodware past 2,000 files from at least 300 products** (Arp P1;
   synthesizer P3). This is the single biggest lever for both FPR confidence and
   threshold room. It needs downloads (Chocolatey/winget/GitHub releases, statically
   unpacked), so it requires approval.
2. **Retrain rf_adv with live goodware.** Its remaining FPs are Go binaries and Python
   launchers that EMBER already scores near zero.
3. **More malware families.** Prioritize low-credibility families (Transcend), then run
   few-shot and learning curves on a time split.
4. **Evaluate an EMBER2024-trained member** with a matching extractor. This needs a large
   download, so it requires approval.
5. **VirusTotal hash-only label audit.** For example, `AA_v3.exe` is Ammyy Admin, a
   remote-admin tool that many vendors classify as RiskTool.

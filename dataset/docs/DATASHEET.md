# Datasheet: retraining dataset for the MLSEC PE defender

Follows the *Datasheets for Datasets* structure (Gebru et al.). Numbers marked
`{FILLED AT BUILD}` come from the manifests the pipeline writes.

## Motivation

Built to retrain and evaluate a static Windows PE malware detector against the
challenge goals (FPR ≤ 1 %, TPR ≥ 95 %) under a realistic threat model. The
supplied model ships without a validation corpus, so no FPR/TPR claim about it can
be checked; this dataset exists to make those numbers measurable and to test
whether retraining on representative, temporally-ordered data improves them.

## Composition

Three sources, each chosen for a specific role.

| Source | Role | Class | Provenance | Labels |
|---|---|---|---|---|
| EMBER 2018 | train + primary temporal test | both | Elastic, `ember_dataset_2018_2` | AV-consensus (published) |
| MalwareBazaar | recent drift test | malicious | abuse.ch, authenticated API | family + first-seen tags |
| Chocolatey | recent goodware FPR test | benign | community package feed, ranked by installs | source-implied benign |

* **EMBER 2018** provides 800k labelled records (400k benign, 400k malicious after
  dropping the 200k deliberately-unlabelled rows). Its per-sample JSON is exactly
  the schema the NFS trainer consumes, so conversion is lossless — including the
  swapped `libraries`/`functions` fields and their space padding.
* **MalwareBazaar** supplies real, recent in-the-wild PE malware, family-stratified
  rather than taken from the raw recent feed (which is ~40 % a single Mirai/ELF
  campaign). Roughly 40 families spanning stealers, RATs, loaders, ransomware,
  bankers, and miners.
* **Chocolatey** supplies current, real benign Windows binaries so that recent
  malware is compared against recent goodware, not against 2018 benign files.

### Instances

An instance is one PE file, represented by the NFS attribute set: 22 numeric
header fields, two categoricals (machine, magic), and five text fields
(libraries, functions, exports, DLL/COFF characteristics). Raw bytes are retained
only for the collected recent samples, for end-to-end container testing.

Counts (`{FILLED AT BUILD}` from `dataset/work/*/manifest.json` and index files):
* EMBER train (months < 2018-11): 600,000 (300k / 300k)
* EMBER temporal test (2018-11..12): 200,000 (100k / 100k)
* Recent malware collected: see `dataset/quarantine/families.json`
* Recent goodware collected: see `dataset/goodware/index.jsonl`

### Labels

EMBER labels are AV-consensus with a published rule and an explicit unlabelled
band, which we drop rather than force. MalwareBazaar labels are family tags from
abuse.ch; VirusTotal lookups (`vt_enrich.py`) add detection ratios and first-seen
dates for cross-checking, within the free tier's 500/day limit. Goodware is
labelled benign by source (popular signed installers), an assumption stated as a
limitation, not a ground truth.

## Collection process

* EMBER downloaded from Elastic, SHA-verified by size, converted in-schema.
* Malware pulled via the authenticated MalwareBazaar API, per family, capped per
  family for diversity. Samples remain AES-encrypted on disk (password `infected`,
  mode 0600) and are decrypted only in memory for feature extraction. **No sample
  is executed.**
* Goodware extracted from `.nupkg` archives from the Chocolatey feed ranked by
  install count. Only embedded PEs (`MZ`-verified) are kept; installers that
  fetch payloads at install time yield nothing and are skipped.

## Preprocessing / cleaning

* Exact-hash deduplication across all EMBER shards (0 duplicates found).
* **Known limit — dedup is by SHA-256 only, not by features.** An audit
  ([PITFALL_AUDIT.md](PITFALL_AUDIT.md) Part 6) found ~15 % of the recent set is
  *feature-identical* to another sample (distinct hash, same extracted attributes —
  repacked variants), and ~18 % of recent-test malware is feature-identical to a
  training row, which inflated the held-out recent number. A feature-fingerprint
  dedup before splitting is the fix; the leakage-corrected numbers are in the audit.
* Unlabelled and unparseable records dropped from training; unparseable *test*
  samples are kept and scored 1 in the EMBER temporal and raw-PE/HTTP evaluations
  (`evaluate_models.py`, `tools/evaluate.py`), matching the server's fail-toward-detection
  rule. **Exception:** the recent MalwareBazaar/Chocolatey split (`split_recent.py`)
  dropped its one unparseable row (a BlackCat sample) before splitting; the tool's
  `--keep-unparseable` option (2026-10-21) carries such rows into the test side, but the
  split `rf_adv` was trained on predates it.
* **EMBER: temporal split on first-seen date**, never random: EMBER train is strictly
  before the cutoff, test strictly after. **The recent set is different:** its
  train/test split is random within family and SHA-disjoint only (not chronological;
  84/433 test malware rows have a feature-identical training twin). It therefore
  measures "new instance of a known family", not forward-in-time generalization
  (PITFALL_AUDIT.md Part 6; `split_recent.py --temporal --group-duplicates` exist for a
  future re-split, which requires retraining). A further inner split (months ≥ 2018-09)
  is the early-stopping validation set, so the 2018-11/12 test period is never seen
  during training or model selection.
* **Adversarial augmentation (single-model `rf_adv` only).** `rf_adv` adds synthetic
  feature-space perturbations of training malware rows (attribute-dict edits generated
  in memory by `tools/adv_transforms.py`; never written as PEs, never validated or
  executed) so the model learns to resist those perturbations. These are a modelling choice, not collected data.
  Robustness is evaluated on the **held-out `recent_test` split** with **held-out
  donors** (so a gain is generalization, not memorization of victims or donor tokens),
  and the fix's limits are reported (no transfer to an untrained mechanism; full mimicry
  still evades). See [COMPARISON_REPORT.md](COMPARISON_REPORT.md) §10.

## Uses and limitations

* The headline metric is **TPR at FPR = 1 %** on the temporal test set, with
  per-family and per-month slices and a Wilson confidence interval.
* EMBER 2018 is, by construction, 2018-vintage; the MalwareBazaar and Chocolatey
  sets exist precisely to test the drift EMBER alone cannot show.
* Goodware collected here skews toward popular open-source/free software and is
  modest in size; it supports a recent-FPR spot check, not a population FPR. The
  large-sample FPR number comes from EMBER's 100k benign test rows.
* Family coverage reflects what MalwareBazaar had recently; rare or targeted
  families are under-represented. This is a availability sample, not a census.

## Distribution and maintenance

Not for redistribution. Malware stays local, encrypted, and 0600. Credentials are
kept outside the repository tree and are git-ignored. The pipeline is
deterministic (fixed seeds) and re-runnable, so the dataset can be rebuilt or
extended as new samples appear.

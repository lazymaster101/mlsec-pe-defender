# Dataset & retraining pipeline

Builds a representative, temporally-ordered dataset for the MLSEC Windows PE
defender and retrains the model on it. Design rationale is in
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md); the dataset is described in
[docs/DATASHEET.md](docs/DATASHEET.md); results are in
[docs/COMPARISON_REPORT.md](docs/COMPARISON_REPORT.md).

## Layout

```
dataset/
  tools/
    build_dataset.py         EMBER 2018 JSONL -> NFS-schema temporal split
    resplit.py               re-cut an existing split at a new month
    collect_malwarebazaar.py recent in-the-wild PE malware, by family (MB_AUTH_KEY)
    collect_goodware.py      current benign PEs from the Chocolatey feed
    vt_enrich.py             VirusTotal label enrichment (VT_API_KEY; lookups only)
    extract_pe.py            collected PEs -> NFS-schema JSONL (in-memory decrypt)
    split_recent.py          family-stratified train/test split of the recent set
    train_nfs.py             RandomForest trainer -> flat runtime arrays
    train_lightgbm.py        GBDT trainer (see report §6 for why RF was chosen)
    evaluate_models.py       FPR/TPR/AUC + per-family/month slices, any model set
    package_model.py         install a model into the image + calibrate threshold
    run_evaluation.sh        one-shot full comparison
  raw/                       EMBER download (git-ignored)
  work/                      derived JSONL splits (git-ignored)
  quarantine/                MalwareBazaar archives, AES-encrypted, 0600 (git-ignored)
  goodware/                  harvested benign PEs (git-ignored)
  models/                    retrained model arrays
  results/                   evaluation JSON
  docs/                      threat model, datasheet, comparison report
```

## Reproduce

Credentials come from the environment and are never written to the repo:

```bash
export VT_API_KEY=...        # free tier: label lookups only, no downloads
export MB_AUTH_KEY=...       # MalwareBazaar auth key
PY=defender_product/.venv/bin/python   # numpy, lief, mmh3, scikit-learn, scipy, pyzipper, certifi
```

```bash
# 1. EMBER 2018 -> temporal split at EMBER's official cutoff
curl -L -o dataset/raw/ember2018.tar.bz2 https://ember.elastic.co/ember_dataset_2018_2.tar.bz2
tar -xjf dataset/raw/ember2018.tar.bz2 -C dataset/raw
$PY dataset/tools/build_dataset.py --ember dataset/raw/ember2018 --out dataset/work/ember --cutoff 2018-08
$PY dataset/tools/resplit.py dataset/work/ember dataset/work/ember_official 2018-11

# 2. Collect recent samples
$PY dataset/tools/collect_malwarebazaar.py --out dataset/quarantine --per-family 40
$PY dataset/tools/collect_goodware.py --out dataset/goodware --packages 1800
$PY dataset/tools/extract_pe.py --malware dataset/quarantine --goodware dataset/goodware --out dataset/work/recent.jsonl
$PY dataset/tools/split_recent.py

# 3. Train (RandomForest, max_features=0.05 is load-bearing; see report §4)
$PY dataset/tools/train_nfs.py --train dataset/work/ember_official/train.jsonl \
    --out dataset/models/nfs_rf_tuned --max-per-class 150000 --max-features 0.05

# 4. Evaluate and calibrate
bash dataset/tools/run_evaluation.sh
$PY dataset/tools/package_model.py --model dataset/models/nfs_rf_tuned --name rf_tuned \
    --calibrate dataset/work/ember_official/test.jsonl --target-fpr 0.01
```

## Safety

Malware is never executed and never decrypted to disk. Archives keep MalwareBazaar's
`infected` password and mode 0600; `extract_pe.py` decrypts only in memory to read
features. API keys live outside the repo tree and are git-ignored. The training
pipeline is deterministic (fixed seeds) and re-runnable.

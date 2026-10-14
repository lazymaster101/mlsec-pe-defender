# MLSec PE Defender

A Windows PE malware classifier served over HTTP from a Docker container. Send it the
bytes of a file; it answers `{"result": 0}` (benign) or `{"result": 1}` (malware).

```
.
├── defender/        Docker build context: HTTP server, model code, weights, eval scripts
├── train/           training script (not shipped in the image)
└── trainedModel/    checkpoints and metrics written by training
```

## The model

The defender uses **MalConv**, a byte-level convolutional neural network that reads the
raw file with no hand-built features and no PE parsing. It runs on CPU with PyTorch.

| Stage            | Detail                                                                    |
|------------------|---------------------------------------------------------------------------|
| Input            | first 1 MiB of the file (`max_bytes = 1048576`), zero-padded if shorter   |
| Embedding        | 257 symbols (bytes 0-255 + padding) x 8 dimensions                        |
| Convolution      | two parallel `Conv1d` layers, 128 filters, kernel 500, stride 500, gated (`ReLU(a) * sigmoid(b)`) |
| Pooling          | global max-pool over positions                                            |
| Classifier       | Dense 128 + ReLU, then Dense 1 + sigmoid -> malware probability           |
| Decision         | `1` if probability >= threshold (default **0.80**), else `0`              |

The weights shipped in the image are `defender/defender/models/malconv_best.pth`. They
are baked in at build time, so after replacing that file you must rebuild the image.
The model code is `defender/defender/models/malconv_model.py`; the training script is
`train/train_malconv.py`.

## Prerequisites

- Docker
- For the evaluation scripts (run on the host, not in the container): Python 3 with
  `requests`, `tqdm` and `numpy`

```bash
pip install requests tqdm numpy
```

## Build and run the container

### Option 1: the helper script

```bash
cd defender
./build_and_test.sh
```

This builds the image `defender_product`, starts a container named `defender_product`
(detached, `--rm`, memory limit `1g`, host port 8080 -> container port 8080), and waits up
to 60 s for `GET /model` to answer. It exits non-zero and prints the container logs if the
service never comes up.

> **Warning:** the script runs `docker rm -f` on any existing container with the same
> name before starting. If a `defender_product` container is already running, it will
> be replaced.

Overrides, passed as environment variables:

| Variable         | Default             | Meaning                                |
|------------------|---------------------|----------------------------------------|
| `IMAGE_NAME`     | `defender_product`  | image tag to build                     |
| `CONTAINER_NAME` | `defender_product`  | container name                         |
| `PORT`           | `8080`              | host port that forwards to the container |
| `READY_TIMEOUT`  | `60`                | seconds to wait for the service        |

```bash
PORT=8090 CONTAINER_NAME=defender_product-2 ./build_and_test.sh
```

### Option 2: plain Docker commands

```bash
cd defender
docker build -t defender_product .
docker run -d --rm --name defender_product -m 1g -p 8080:8080 defender_product
```

### Stop, logs, and tuning

```bash
docker logs -f defender_product     # follow server logs
docker stop defender_product        # --rm removes the container on stop
```

The server reads three environment variables, so a different threshold needs no rebuild.
Use plain `docker run` for this, because the helper script does not pass them:

```bash
docker run -d --rm --name defender_product -m 1g -p 8080:8080 \
    -e DF_MALCONV_THRESH=0.90 defender_product
```

| Variable               | Default                    | Meaning                                              |
|------------------------|----------------------------|------------------------------------------------------|
| `DF_MALCONV_THRESH`    | `0.80`                     | flag as malware when probability >= this value       |
| `DF_MALCONV_MAX_BYTES` | `1048576`                  | bytes read from each file (truncate / zero-pad)      |
| `DF_MALCONV_WEIGHTS`   | `models/malconv_best.pth`  | weights path; relative paths resolve inside `defender/defender/` |

## API

| Method | Path     | Request                                                | Response                                    |
|--------|----------|--------------------------------------------------------|---------------------------------------------|
| POST   | `/`      | file bytes, `Content-Type: application/octet-stream`   | `{"result": 0}` or `{"result": 1}`          |
| GET    | `/model` | none                                                   | `{"name", "max_bytes", "threshold", "device"}` |

The `Content-Type` header must be exactly `application/octet-stream`, or the server
answers `400`.

```bash
curl -s http://127.0.0.1:8080/model

curl -s -X POST -H "Content-Type: application/octet-stream" \
     --data-binary @/path/to/sample.exe http://127.0.0.1:8080/
```

## Measure accuracy, precision, recall, F1 and FPR

`build_and_test.sh` only builds, starts and health-checks the container. The metrics come
from the evaluation harness in `defender/test/`, which sends your goodware and malware
files to the running container and compares the answers with the known labels.

Run it from the `defender/` directory:

```bash
cd defender
python3 -m test -m /path/to/malware -b /path/to/goodware
```

| Flag          | Default                  | Meaning                                                      |
|---------------|--------------------------|--------------------------------------------------------------|
| `-m`          | required                 | malware samples: a folder, `.zip`, `.tar`, `.tar.gz`/`.tgz`, or `.tar.bz2` |
| `-b`          | required                 | goodware samples, same formats                               |
| `--url`       | `http://127.0.0.1:8080/` | address of the running container                             |
| `--stopafter` | `5000`                   | maximum files tested **per class**                           |
| `--max`       | `2097152` (2 MiB)        | skip files larger than this                                  |
| `--timeout`   | `5`                      | per-request timeout in seconds                               |
| `--out-dir`   | the `-b` folder          | where result files are written                               |

Malware is the positive class. It prints a confusion matrix and the metrics:

```
Confusion matrix:
  TP=... TN=... FP=... FN=...
  Accuracy:  0.xxxx
  Precision: 0.xxxx
  Recall:    0.xxxx      (this is the true positive rate, TPR)
  F1:        0.xxxx
```

and writes four files to `--out-dir`:

| File           | Contents                                                                 |
|----------------|--------------------------------------------------------------------------|
| `summary.json` | all metrics, plus `fp` (= **FPR**), `fn` (= false negative rate), `errors`, `avg_time`, `max_time` |
| `fps.txt`      | goodware files flagged as malware                                        |
| `fns.txt`      | malware files that were missed                                           |
| `errors.txt`   | requests that failed or timed out, with the error message                |

Things that affect the numbers:

- Only files that start with the `MZ` header and are at most `--max` bytes are tested;
  everything else is silently skipped. Folders are **not** searched recursively.
- A request that errors or times out is scored as benign (`0`), so on malware it counts
  as a false negative. Check `errors.txt` if recall looks low.
- By default the result files are written **into your goodware folder**; pass `--out-dir`
  to keep that folder clean.
- Malware is tested first, then goodware.

### Scan files without labels

To get a verdict per file and a CSV, without computing metrics:

```bash
cd defender
python3 tools/batch_scan.py --dir /path/to/files --recursive --pattern "*.exe" \
        --workers 8 --out-csv scan_results.csv
```

The CSV columns are `path,result,status,error`. Options: `--url`, `--timeout`,
`--max-files`, `--print-jsonl`.

## Troubleshooting

- **`port is already allocated`**: something already uses 8080. Pick another port
  (`PORT=8090 ./build_and_test.sh`, or `-p 8090:8080`) and pass
  `--url http://127.0.0.1:8090/` to the evaluation scripts. Use `docker ps` to see what
  holds 8080.
- **`python3 -m test` does something unexpected or fails on imports**: run it from inside
  `defender/`. The harness is a local package named `test`, which only shadows Python's
  own `test` package when `defender/` is the current directory.

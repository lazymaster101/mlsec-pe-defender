# Sure-shot submission (v3, frozen)

`submission/` is exactly the contents of `mlsec-defender-submission.zip`: one Dockerfile,
`python:3.12-slim`, and PyPI/Debian-only dependencies, fully pinned (direct and transitive).
This branch is frozen. Development continues on `dev/v4`.

## What is verified (2026-10-18)

The released course set `csce704-blackbox-validation-100-samples-20261014-corrected`
(50 malware / 50 goodware) was graded over HTTP against the built container. The container
ran offline (`--network none`), with 1 CPU, 1 GiB RAM and swap, a read-only root
filesystem and non-root uid 10001.

| Build | TP | FP | TPR | FPR | Result | Ready | p95 latency | Memory |
|---|---|---|---|---|---|---|---|---|
| linux/arm64 | 48/50 | 0/50 | 96.0% | 0.0% | **PASS** | 3 s | 54 ms | 189 MiB |
| linux/amd64 | 48/50 | 0/50 | 96.0% | 0.0% | **PASS** | 6 s* | 88 ms* | 234 MiB |

\* amd64 ran under emulation on an ARM Mac, so native x86 will be faster.

- Per-sample fusion scores are **bit-identical** across arm64 and amd64 (maximum
  difference 0.0), so verdicts do not depend on the grader's CPU architecture.
- Builds take about 25–35 s (limit 300 s). The ZIP is 42 MB (limit 512 MiB) and contains
  no PE files.
- The decision threshold was chosen on our own data only. The grading set was used once,
  after freezing, to check the result; it was never used for tuning.

## What is and is not guaranteed

- **Guaranteed:** on the released 50/50 set this build passes deterministically.
  The weakest caught malware sits 0.42 logit above the threshold. 48/50 goodware are
  cleared by Microsoft Authenticode trust, and the other 2 sit at least 3.0 logit below.
- **Zero slack in the count:** 48/50 is the minimum passing TPR (>95%). Losing one more
  detection fails the bar.
- **Not guaranteed:** if graders use a *different*, unseen set, no static detector can
  promise TPR > 95%. Our family-held-out estimate is about 83.5% ± 4.1% TPR at about 0.1%
  overall FPR (about 1.1% on goodware EXEs). See `dataset/docs/V3_DETECTOR.md`.

## Reproduce

```bash
cd submission && docker build -t defender .
docker run -d --name d --read-only --network none --cpus=1 -m 1g --memory-swap 1g --tmpfs /tmp defender
docker run --rm --network container:d -v "$SET":/gs:ro -v "$PWD/../dataset/tools/grade_http.py":/g.py:ro \
  python:3.12-slim python -I /g.py /gs   # exits 0 on PASS
```

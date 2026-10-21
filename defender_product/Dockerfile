# Self-contained MLSEC defender: Windows PE malware classifier over HTTP.
# Runtime needs neither scikit-learn nor the original pickle -- the forest ships
# as plain .npy arrays that are memory-mapped, so the resident set tracks the
# nodes actually visited rather than the full 380 MB on disk.
FROM python:3.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    DF_MODEL_DIR=/app/models/rf_adv \
    DF_MALWARE_THRESHOLD=0.820932 \
    DF_FEATURE_MODE=training \
    DF_REQUEST_BUDGET_SECONDS=4.5 \
    DF_WORKER_MODE=process \
    DF_WORKERS=1 \
    DF_HOST=0.0.0.0 \
    DF_PORT=8080

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
 && groupadd -r defender \
 && useradd --no-log-init -r -g defender -u 10001 defender

# Ship only the deployed adversarially-trained model (59 MB). The supplied 398 MB
# model, the clean rf_augmented, and the EMBER-only rf_tuned live in the repo's
# dataset/ for comparison.
COPY models/rf_adv ./models/rf_adv
COPY defender/ ./defender/
COPY LICENSE.upstream ./LICENSE.upstream

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"]

CMD ["python", "-m", "defender.server"]

# Build:  docker build -t mlsec-defender .
# Run:    docker run --rm -m 1g -p 8080:8080 mlsec-defender
# Query:  curl -XPOST --data-binary @sample.exe -H "Content-Type: application/octet-stream" http://127.0.0.1:8080/

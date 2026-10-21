# v3.2 defender: Authenticode trust/tamper layers (+ the two pre-2010 Microsoft Code
# Signing PCA generations), the embedded hidden-PowerShell command-line tell, and the
# log-odds fusion of ember_gbdt, rf_adv and ember_ft_v32 (800-round continued boosting on
# 1,705 recent malware incl. 250 fresh tagged/feed samples;
# see defender/ensemble.py). CPU-only, offline, well within the
# 1 GB / 5 s budget.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OPENBLAS_NUM_THREADS=1 \
    OMP_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    DF_EMBER_MODEL=/app/models/ember_gbdt/ember_gbdt.txt \
    DF_RF_DIR=/app/models/rf_adv \
    DF_EMBER_FT=/app/models/ember_ft_v32/ember_ft.txt \
    DF_FUSION=/app/models/fusion_v32.json \
    DF_HOST=0.0.0.0 \
    DF_PORT=8080

WORKDIR /app

# LightGBM needs the OpenMP runtime (libgomp), absent in slim images.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.ensemble.txt ./
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.ensemble.txt \
 && groupadd -r defender \
 && useradd --no-log-init -r -g defender -u 10001 defender

COPY defender/ ./defender/
COPY models/rf_adv ./models/rf_adv
COPY models/ember_gbdt ./models/ember_gbdt
COPY models/ember_ft_v32 ./models/ember_ft_v32
COPY models/fusion_v32.json ./models/fusion_v32.json
COPY LICENSE.upstream ./LICENSE.upstream

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"]

CMD ["python", "-m", "defender.ensemble_server"]

# Build:  docker build -t mlsec-defender:v32 .
# Run:    docker run --rm -m 1g -p 8080:8080 mlsec-defender:v32

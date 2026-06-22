# Calus proxy + detection engine — single image.
# Build context is the repo root so the sibling `calus/` engine is available.
# Pinned base image (digest-style tag) for reproducible builds.
FROM python:3.12.7-slim-bookworm

WORKDIR /app

# install the engine first (its own layer → cached unless engine changes)
COPY calus/ ./calus/
RUN pip install --no-cache-dir -e ./calus

# proxy deps + source
COPY proxy/requirements.txt ./proxy/requirements.txt
RUN pip install --no-cache-dir -r ./proxy/requirements.txt
COPY proxy/ ./proxy/

# persist the SQLite log store outside the layer
ENV CALUS_DB_PATH=/data/calus_proxy.db
VOLUME ["/data"]

# run as a non-root user; give it ownership of the data + app dirs
RUN useradd --create-home --uid 10001 calus \
    && mkdir -p /data \
    && chown -R calus:calus /data /app
USER calus

EXPOSE 8000
WORKDIR /app/proxy

# container healthcheck hits the readiness gate (503 until detector is warm)
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status==200 else 1)" || exit 1

# detection-only gateway; binds all interfaces inside the container
CMD ["python", "-m", "uvicorn", "calus_proxy.main:app", "--host", "0.0.0.0", "--port", "8000"]

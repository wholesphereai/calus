# Calus proxy + detection engine — single image.
# Build context is the repo root so the sibling `calus/` engine is available.
FROM python:3.12-slim

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

EXPOSE 8000
WORKDIR /app/proxy
# detection-only gateway; binds all interfaces inside the container
CMD ["python", "-m", "uvicorn", "calus_proxy.main:app", "--host", "0.0.0.0", "--port", "8000"]

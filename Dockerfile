FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .
COPY client/ /app/client/

# Non-root user for security
RUN useradd -r -s /bin/false appuser && \
    mkdir -p /data/files && \
    chown -R appuser:appuser /data

USER appuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]

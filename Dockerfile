FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py .
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8600/health || exit 1
EXPOSE 8600
CMD ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8600", "--workers", "1"]

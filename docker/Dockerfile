FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir . 2>/dev/null || pip install --no-cache-dir \
    fastapi uvicorn[standard] pydantic pydantic-settings httpx \
    chromadb numpy scikit-learn pyyaml structlog websockets \
    aiofiles python-dateutil jinja2

COPY src/ src/
COPY config/ config/

EXPOSE 8080

ENV PYTHONPATH=/app
ENV LOG_LEVEL=INFO

CMD ["python", "-m", "src.main"]

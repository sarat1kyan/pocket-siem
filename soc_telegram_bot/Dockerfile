# ── Build stage ───────────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build
COPY pyproject.toml .
RUN pip install --no-cache-dir hatchling && \
    pip install --no-cache-dir \
        fastapi \
        uvicorn[standard] \
        python-telegram-bot \
        httpx \
        pydantic \
        pydantic-settings \
        sqlalchemy \
        aiosqlite \
        asyncpg \
        tenacity \
        python-json-logger \
        python-dotenv

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM python:3.11-slim AS runtime

# Non-root user for security
RUN groupadd -r socbot && useradd -r -g socbot -m -d /app socbot

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app/ ./app/

# Data directory for SQLite (will be overridden by volume in compose)
RUN mkdir -p /app/data && chown -R socbot:socbot /app

USER socbot

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

EXPOSE 8080

CMD ["python", "-m", "app.main"]

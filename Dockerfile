# syntax=docker/dockerfile:1

# Stage 1: build the frontend
FROM node:20-slim AS frontend-build
WORKDIR /build/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: production image (API + served frontend)
FROM python:3.13-slim AS production
WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app/backend \
    SENTINEL_PORT=8080 \
    SENTINEL_SERVE_FRONTEND=true

# Install runtime dependencies from the backend manifest.
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy application source.
COPY backend/ /app/backend/
COPY scenarios/ /app/scenarios/

# Copy the built frontend.
COPY --from=frontend-build /build/frontend/dist/ /app/frontend/dist/

# Run as an unprivileged user.
RUN useradd --create-home --uid 10001 sentinel \
    && chown -R sentinel:sentinel /app
USER sentinel

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')" || exit 1

CMD ["python", "-m", "sentinel.dev_server", "--serve-frontend"]

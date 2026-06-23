FROM node:20-slim AS node-deps
WORKDIR /scripts
COPY scripts/package.json scripts/package-lock.json* ./
RUN if [ -f package-lock.json ]; then npm ci --production; else npm install --production; fi

# Build Tailwind CSS at image build time
FROM node:20-slim AS tailwind-build
WORKDIR /build
RUN npm install -g tailwindcss@3
COPY tailwind.config.js ./
COPY app/dashboard/static/src/input.css ./app/dashboard/static/src/input.css
COPY app/dashboard/templates/ ./app/dashboard/templates/
RUN npx tailwindcss -i ./app/dashboard/static/src/input.css -o ./dashboard.min.css --minify

FROM python:3.12-slim

WORKDIR /app

# System deps + copy Node.js from builder stage
# gnupg is required at runtime: operators.py verifies the signed
# operator registry (operators.sig.asc) via an isolated GnuPG keyring
# at startup; without it the loader cannot verify against the pinned
# release-key fingerprint and the API refuses to start.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    gnupg \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY --from=node-deps /usr/local/bin/node /usr/local/bin/node
COPY --from=node-deps /usr/local/lib/node_modules /usr/local/lib/node_modules
RUN ln -s /usr/local/lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm

# Install Python dependencies (cached until pyproject.toml changes)
COPY pyproject.toml ./
RUN pip install --no-cache-dir $(python3 -c "import tomllib; print(' '.join(tomllib.load(open('pyproject.toml','rb'))['project']['dependencies']))")

# Copy Node.js claim script dependencies from builder
COPY scripts/package.json scripts/package-lock.json* scripts/
COPY --from=node-deps /scripts/node_modules scripts/node_modules

# Copy application code & install package
COPY . .
COPY --from=tailwind-build /build/dashboard.min.css app/dashboard/static/dashboard.min.css
RUN pip install --no-cache-dir --no-deps .

# Non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 8100

# Image-level liveness probe so every consumer (compose, plain `docker run`,
# orchestrators) inherits the same /livez check. The compose `api` service
# pins matching parameters; non-compose consumers fall back to these.
HEALTHCHECK --interval=60s --timeout=10s --start-period=120s --retries=3 \
    CMD curl -fsS http://localhost:8100/livez || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8100"]

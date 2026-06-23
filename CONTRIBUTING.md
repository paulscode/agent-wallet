# Contributing to Agent Wallet

Thank you for your interest in contributing! This guide will help you get started.

## Code of Conduct

Please be respectful and constructive in all interactions. We follow the [Contributor Covenant](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## Development Setup

### Prerequisites

- Python 3.11+
- Node.js 20+ (for Boltz Musig2 claim scripts)
- PostgreSQL 15+ (for production; tests use SQLite)
- Redis 7+

### Local Environment

```bash
# Clone the repo
git clone https://github.com/paulscode/agent-wallet.git
cd agent-wallet

# Set up Python virtual environment
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Set up Node.js dependencies (for Boltz claim scripts)
cd scripts && npm install && cd ..

# Copy and configure environment
cp .env.example .env
# Edit .env with your local settings (SQLite works for basic dev)
```

### Running Tests

Tests use an in-memory SQLite database — no PostgreSQL or Redis required.

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=app --cov-report=term-missing

# Run only unit tests
pytest tests/unit/

# Run only integration tests
pytest tests/integration/
```

### Linting & Type Checking

```bash
# Lint with ruff
ruff check .
ruff format --check .

# Type check with mypy
mypy app/
```

## Making Changes

### Branch Naming

- `feature/short-description` — new features
- `fix/short-description` — bug fixes
- `docs/short-description` — documentation only
- `refactor/short-description` — code refactoring

### Pull Request Process

1. Fork the repository and create your branch from `main`.
2. Write tests for any new functionality.
3. Ensure all tests pass: `pytest`
4. Ensure linting passes: `ruff check .`
5. Ensure type checking passes: `mypy app/`
6. Update documentation if your change affects the API or configuration.
7. Open a pull request with a clear description of the change.

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add velocity rate limiting for payments
fix: correct migration column names for boltz_swaps
docs: update README with new configuration options
test: add integration tests for health endpoint
```

## Code Style

- **Line length:** 120 characters (configured in `pyproject.toml`)
- **Formatting:** Follow ruff defaults
- **Type hints:** Required for all function signatures (`disallow_untyped_defs = true`)
- **Docstrings:** Required for public functions and classes
- **Security:** Never log secrets, credentials, or API keys

## Architecture Notes

- **`app/core/`** — Configuration, database, security, encryption
- **`app/api/`** — FastAPI routers (thin layer, delegates to services)
- **`app/services/`** — Business logic (LND, Boltz, Mempool, audit)
- **`app/models/`** — SQLAlchemy ORM models
- **`app/tasks/`** — Celery background tasks (Boltz swap processing)
- **`scripts/`** — Node.js scripts (Boltz Musig2 claim transactions)
- **`tests/unit/`** — Unit tests (mock external services)
- **`tests/integration/`** — Integration tests (full HTTP request cycle)

## Documentation

User-facing feature guides live under [`docs/`](docs/) (see the
[docs index](docs/README.md)). When adding or changing a feature, keep `docs/`
focused on what an end user or operator needs to know — background, architecture
summary, configuration, and runbook material — and avoid embedding deep design
rationale.

For deeper design discussion — plans, threat models, and implementation
trade-offs — use the issue or pull request where the change is proposed, so the
rationale stays visible to reviewers and is captured in the project history.

## Security

If you discover a security vulnerability, **do not open a public issue**. See [SECURITY.md](SECURITY.md) for responsible disclosure instructions.

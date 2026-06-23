# Developer convenience targets. The CI workflow (.github/workflows/ci.yml) is
# the authoritative pipeline; these mirror its common steps for local use.
.PHONY: test test-cov test-cov-html guardrails lint typecheck

# Behavioral test suite with branch coverage, parallelized. Coverage settings
# (branch, omit, fail_under) come from pyproject.toml, so this prints the same
# number CI enforces. Excludes the source-structure guardrail tests.
test-cov:
	pytest -n auto -m "not guardrail" --cov=app --cov-report=term-missing

# Same, plus a browsable HTML report under htmlcov/.
test-cov-html:
	pytest -n auto -m "not guardrail" --cov=app --cov-report=term-missing --cov-report=html

# Source-structure / supply-chain guardrail assertions (no app coverage value).
guardrails:
	pytest -m guardrail

# Fast behavioral run, no coverage.
test:
	pytest -n auto -m "not guardrail"

lint:
	ruff check .
	ruff format --check .

typecheck:
	mypy app/

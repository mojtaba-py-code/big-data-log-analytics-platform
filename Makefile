# Developer shortcuts.  Everything here is also what CI runs.
.DEFAULT_GOAL := help
.PHONY: help install lint format typecheck test test-all security check demo bench clean docker

PYTHON ?= python
SOURCES := app tests

help:  ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install the package with development extras
	$(PYTHON) -m pip install -e ".[dev,postgres,api]"

lint:  ## Ruff lint
	ruff check $(SOURCES)

format:  ## Ruff format (writes)
	ruff format $(SOURCES)
	ruff check --fix $(SOURCES)

typecheck:  ## MyPy in strict mode
	mypy app

test:  ## Fast suite (unit + integration + security)
	pytest -m "not slow" -q

test-all:  ## Everything, including the performance suite, with coverage
	pytest --cov=app --cov-report=term-missing --cov-report=html

security:  ## Static analysis and dependency audit
	bandit -c pyproject.toml -r app
	pip-audit

check: lint typecheck test security  ## Everything CI runs

demo:  ## End-to-end demonstration, then serve the dashboard
	$(PYTHON) scripts/demo_end_to_end.py --records 200000 --serve

bench:  ## Benchmark and write results
	$(PYTHON) benchmarks/benchmark.py --records 100000 --output benchmarks/results/local.json

docker:  ## Build and smoke-test the container image
	docker build -t big-data-log-analytics:local .
	docker run --rm big-data-log-analytics:local --version

clean:  ## Remove caches and build artefacts
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage
	find . -type d -name __pycache__ -prune -exec rm -rf {} +

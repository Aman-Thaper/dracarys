# DRACARYS developer workflow. Run `make help` for the list.
VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

.DEFAULT_GOAL := help

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

$(VENV): ## Create the virtualenv
	python3 -m venv $(VENV)

.PHONY: setup
setup: $(VENV) ## Create venv, install backend (editable) + dev deps
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[dev,llm]"
	@echo "Backend ready. Run 'make web-setup' for the frontend."

.PHONY: web-setup
web-setup: ## Install frontend dependencies
	cd web && npm install --no-audit --no-fund

.PHONY: migrate
migrate: ## Apply database migrations
	$(VENV)/bin/alembic upgrade head

.PHONY: api
api: ## Run the control-plane API (http://127.0.0.1:8000)
	$(VENV)/bin/uvicorn dracarys.api.app:app --host 127.0.0.1 --port 8000 --reload

.PHONY: lab-up
lab-up: ## Run the vulnerable lab as a standalone service (:8888)
	$(PY) -m lab.run --host 127.0.0.1 --port 8888

.PHONY: web
web: ## Run the frontend command center (http://localhost:3000)
	cd web && npm run dev

.PHONY: demo
demo: ## Run a full headless campaign and print a report
	$(VENV)/bin/dracarys demo

.PHONY: eval
eval: ## Run a campaign and score it against ground truth
	$(VENV)/bin/dracarys eval

.PHONY: selftest
selftest: ## Score the generic scanner against independent apps
	$(VENV)/bin/dracarys scan-selftest

.PHONY: scan
scan: ## Scan a URL (usage: make scan URL=http://127.0.0.1:3000)
	$(VENV)/bin/dracarys scan $(URL)

.PHONY: test
test: ## Run the full test suite
	$(PY) -m pytest

.PHONY: e2e
e2e: ## Run the end-to-end tests only
	$(PY) -m pytest tests/e2e -v

.PHONY: cov
cov: ## Run tests with a coverage report
	$(PY) -m pytest --cov=dracarys --cov=lab --cov-report=term-missing

.PHONY: lint
lint: ## Lint with ruff
	$(VENV)/bin/ruff check dracarys lab tests

.PHONY: fmt
fmt: ## Auto-format / fix with ruff
	$(VENV)/bin/ruff check --fix dracarys lab tests
	$(VENV)/bin/ruff format dracarys lab tests

.PHONY: typecheck
typecheck: ## Type-check with mypy
	$(VENV)/bin/mypy dracarys

.PHONY: web-build
web-build: ## Production-build the frontend (also type-checks)
	cd web && npm run build

.PHONY: check
check: lint test ## Lint + test (what CI runs)

.PHONY: compose-up
compose-up: ## Bring up the full stack with Docker Compose
	docker compose up --build

.PHONY: compose-down
compose-down: ## Tear down the Docker Compose stack
	docker compose down -v

.PHONY: reset
reset: ## Remove local dev database and caches
	rm -f dracarys.db
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	@echo "Local state reset."

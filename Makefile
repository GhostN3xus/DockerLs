.PHONY: install dev lint type-check test test-build security audit build build-secure run clean

install:
	pip install .

dev:
	pip install -e ".[dev,keyring]"

lint:
	ruff check dockerls/ tests/
	ruff format --check dockerls/ tests/

format:
	ruff format dockerls/ tests/
	ruff check --fix dockerls/ tests/

type-check:
	mypy dockerls/

test:
	pytest tests/ -v --cov=dockerls --cov-report=term-missing

# Just the `dockerls build` surface: parser, rules, templates, builder, CLI.
test-build:
	pytest tests/unit/infrastructure/test_dockerfile_parser.py \
	       tests/unit/infrastructure/test_dockerfile_security_rules.py \
	       tests/unit/infrastructure/test_buildkit_arguments.py \
	       tests/unit/infrastructure/test_docker_builder.py \
	       tests/unit/infrastructure/test_hardening_config.py \
	       tests/unit/domain/test_build_score.py \
	       tests/unit/domain/test_hardening_templates.py \
	       tests/unit/application/test_build_image_use_case.py \
	       tests/unit/application/test_hardening_suggester.py \
	       tests/unit/exporters/test_build_report_exporter.py \
	       tests/unit/cli/test_build_command.py -v

security:
	bandit -r dockerls/ -c pyproject.toml
	pip-audit

audit: lint type-check test security

build:
	docker build -t dockerls:latest .

# Dogfooding: build our own image through our own gate.
build-secure:
	dockerls build . --tag dockerls:latest --scan --report build-report.html

run:
	docker run --rm --read-only --cap-drop=ALL --security-opt=no-new-privileges dockerls:latest

clean:
	rm -rf build/ dist/ *.egg-info .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

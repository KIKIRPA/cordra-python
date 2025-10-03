# Makefile for cordra-python development

.PHONY: help install develop test test-unit test-integration lint format type-check clean build docs

# Default target
help:
	@echo "Available targets:"
	@echo "  install       - Install the package in development mode"
	@echo "  develop       - Set up development environment"
	@echo "  test          - Run all tests"
	@echo "  test-unit     - Run unit tests only"
	@echo "  test-integration - Run integration tests (requires Cordra server)"
	@echo "  lint          - Run linting checks"
	@echo "  format        - Format code with black and isort"
	@echo "  type-check    - Run mypy type checking"
	@echo "  clean         - Clean build artifacts"
	@echo "  build         - Build distribution packages"
	@echo "  docs          - Build documentation"
	@echo "  release       - Create and upload release to PyPI"

# Installation
install:
	pip install -e .

develop:
	pip install -e ".[dev]"

# Testing
test:
	pytest tests/

test-unit:
	pytest tests/ -m "unit"

test-integration:
	pytest tests/ -m "integration"

# Code quality
lint:
	flake8 cordra tests
	black --check cordra tests
	isort --check-only cordra tests

format:
	black cordra tests
	isort cordra tests

type-check:
	mypy cordra

# Cleaning
clean:
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	find . -type d -name __pycache__ -delete

# Building
build:
	python -m build

# Documentation
docs:
	sphinx-build -b html docs/source docs/build

# Release (requires proper PyPI credentials)
release: clean build
	twine upload dist/*

# Development workflow
check-all: lint type-check test-unit

# Quick development cycle
dev: format check-all

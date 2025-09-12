.PHONY: help install test test-all test-idempotency clean init start stop restart rebuild status destroy

help:
	@echo "Docker MITM Bridge - Available Commands"
	@echo "======================================="
	@echo "  make install         - Install Python dependencies"
	@echo "  make init           - Initialize network and start proxy"
	@echo "  make start          - Start the proxy"
	@echo "  make stop           - Stop the proxy"
	@echo "  make restart        - Restart the proxy (docker compose restart)"
	@echo "  make rebuild        - Rebuild and redeploy with config changes"
	@echo "  make status         - Show status"
	@echo "  make destroy        - Remove everything"
	@echo "  make test           - Run main test suite"
	@echo "  make test-idempotency - Run idempotency tests"
	@echo "  make test-all       - Run all tests"
	@echo "  make clean          - Clean up all resources"

install:
	@echo "Installing dependencies..."
	@if [ ! -d .venv ]; then \
		~/.local/bin/uv venv || python3 -m venv .venv; \
	fi
	@. .venv/bin/activate && ~/.local/bin/uv pip install -r requirements.txt || pip install -r requirements.txt

init: install
	@echo "Initializing Docker MITM Bridge..."
	@. .venv/bin/activate && python docker-mitm-bridge init

start: install
	@echo "Starting proxy..."
	@. .venv/bin/activate && python docker-mitm-bridge start

stop: install
	@echo "Stopping proxy..."
	@. .venv/bin/activate && python docker-mitm-bridge stop

restart: install
	@. .venv/bin/activate && python docker-mitm-bridge restart

rebuild: install
	@echo "Rebuilding and redeploying with configuration changes..."
	@. .venv/bin/activate && python docker-mitm-bridge stop
	@. .venv/bin/activate && python docker-mitm-bridge start

status: install
	@. .venv/bin/activate && python docker-mitm-bridge status

destroy: install
	@echo "Destroying all resources..."
	@. .venv/bin/activate && python docker-mitm-bridge destroy

test: install
	@echo "Running test suite..."
	@. .venv/bin/activate && timeout 60 python test_suite.py || (echo "Test timed out or failed"; exit 1)

test-idempotency: install
	@echo "Running idempotency tests..."
	@. .venv/bin/activate && timeout 60 python test_idempotency.py || (echo "Test timed out or failed"; exit 1)

test-all: install
	@echo "Running all tests with timeout..."
	@. .venv/bin/activate && timeout 120 bash -c "python test_suite.py && python test_idempotency.py" || (echo "Tests timed out or failed"; exit 1)
	@echo "All tests completed!"

clean: destroy
	@echo "Cleaning up Docker resources..."
	@docker rm -f $$(docker ps -aq --filter name=test-mitm) 2>/dev/null || true
	@docker rm -f mitm-boundary-proxy 2>/dev/null || true
	@docker network rm mitm-filtered 2>/dev/null || true
	@docker compose down -v 2>/dev/null || true
	@echo "Cleanup complete!"

build:
	@echo "Building Docker image..."
	@docker compose build
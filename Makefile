# SPECTRE orchestration targets. Run from the spectre_swarm root.
.PHONY: help up models build run down clean test

TARGET          ?= /target
SEMGREP_CONFIG  ?= /app/scripts/semgrep_cpp.yaml
FUZZ_TIMEOUT    ?= 60
COMPOSE         := docker compose -f docker/docker-compose.yml

help:
	@echo "make up       - start db + ollama"
	@echo "make models   - pull qwen2.5-coder + nomic-embed-text"
	@echo "make build    - build the agent image"
	@echo "make run      - run SPECTRE against TARGET=$(TARGET)"
	@echo "make down     - stop services"
	@echo "make clean    - stop services and remove volumes"
	@echo "make test     - run the pytest suite"

up:
	$(COMPOSE) up -d db ollama

models:
	$(COMPOSE) exec ollama ollama pull qwen2.5-coder:7b
	$(COMPOSE) exec ollama ollama pull nomic-embed-text

build:
	$(COMPOSE) build agent

run:
	$(COMPOSE) run --rm agent --semgrep-config $(SEMGREP_CONFIG) --fuzz-timeout $(FUZZ_TIMEOUT) $(TARGET)

down:
	$(COMPOSE) down

clean:
	$(COMPOSE) down -v

test:
	python -m pytest

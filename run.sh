#!/usr/bin/env bash
# SPECTRE runner: boots pgvector + Ollama, pulls models, builds and runs the agent.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/docker" && pwd)"
TARGET="${1:-/target}"
SEMGREP_CONFIG="${SEMGREP_CONFIG:-/app/scripts/semgrep_cpp.yaml}"
FUZZ_TIMEOUT="${FUZZ_TIMEOUT:-60}"

cd "$ROOT"

echo "[1/4] Starting db + ollama..."
docker compose up -d db ollama

echo "[2/4] Pulling Ollama models..."
docker compose exec ollama ollama pull qwen2.5-coder:7b
docker compose exec ollama ollama pull nomic-embed-text

echo "[3/4] Building agent image..."
docker compose build agent

echo "[4/4] Running SPECTRE against: $TARGET"
docker compose run --rm agent \
  --semgrep-config "$SEMGREP_CONFIG" \
  --fuzz-timeout "$FUZZ_TIMEOUT" \
  "$TARGET"

echo "Reports written to: $ROOT/../reports"

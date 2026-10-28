# SPECTRE

Enjambre multi-agente para detección automatizada de vulnerabilidades en repositorios
C/C++ (Bug Bounty / SAST), orquestado por **LangGraph** y asistido por LLMs locales
(**Ollama**).

Combina análisis estático (Semgrep + Joern/CPG), análisis dinámico (AFL++ + ASAN),
memoria vectorial (pgvector), deduplicación por stack-trace, cola de eventos (Redis),
observabilidad (OpenTelemetry) y generación de reportes listos para HackerOne.

```
START → recon → semgrep → memory → joern → fuzzer → report → END
                                    ↑         |
                                    +─evasion─+   (si WAF, acotado)
```

## Inicio rápido (Docker)

```bash
cd docker
docker compose up -d db ollama redis
docker compose exec ollama ollama pull qwen2.5-coder:7b
docker compose exec ollama ollama pull nomic-embed-text
docker compose build agent
docker compose run --rm agent --semgrep-config /app/scripts/semgrep_cpp.yaml /target
```

## Inicio rápido (local, solo SAST + reporte)

```bash
pip install -r requirements.txt semgrep
python main.py docker/target --semgrep-config scripts/semgrep_cpp.yaml --no-joern --no-fuzzer
```

## Descubrimiento de objetivos

```bash
python main.py targets list --platform hackerone --query github
python main.py targets search github.com
python main.py targets chaos --program Aiven
```

## Pruebas

```bash
python -m pytest                 # unit (74 tests)
pytest --run-integration         # + Redis/pgvector (requiere servicios arriba)
```

## Documentación

Ver **[AGENTS.md](AGENTS.md)** para la operación completa del enjambre, variables
de entorno, seguridad de la infraestructura y convenciones del código.

# SPECTRE — Operación del Enjambre

SPECTRE es un enjambre multi-agente para detección de vulnerabilidades en
repositorios C/C++ (Bug Bounty / SAST), orquestado por LangGraph sobre un grafo
**cíclico** y asistido por LLMs locales (Ollama).

## Arquitectura

```
START → recon → semgrep → memory → joern → fuzzer → report → END
                                    ↑         |
                                    +─evasion─+   (si WAF, acotado)
```

| Nodo | Módulo | Función |
|---|---|---|
| recon | `graph.recon_node` + `targets` | Descubre scope autorizado (bounty-targets-data / Chaos / BBRF) |
| semgrep | `semgrep_node` | SAST (patrones + taint) → `SemgrepFinding` |
| memory | `memory_node` | Caché de falsos positivos en pgvector (fail-open) |
| joern | `joern_node` + `scripts/pointer_taint.sc` | Análisis CPG (dataflow) |
| fuzzer | `fuzzer_node` | AFL++ + ASAN, seeds dirigidos por `seedgen`, dedup por stack-trace, publica `new_crash` |
| evasion | `graph.evasion_node` + `evasion` | Rotación SOCKS5 ante WAF (bucle acotado) |
| report | `report_node` | Reporte Markdown 4 secciones (Summary/Repro/PoC/Impact) |

Módulos transversales: `events` (cola Redis), `dedup` (hash de stack), `telemetry`
(OTel), `isolation` (gVisor/Firecracker), `vectordb` (asyncpg), `ast` (tree-sitter).

## Inicio rápido

### Docker (stack completo)

```bash
cd docker
docker compose up -d db ollama redis            # memoria + LLM + cola
docker compose exec ollama ollama pull qwen2.5-coder:7b
docker compose exec ollama ollama pull nomic-embed-text
docker compose build agent
docker compose run --rm agent --semgrep-config /app/scripts/semgrep_cpp.yaml /target
```

Observabilidad opcional: `docker compose up -d otel-collector loki prometheus grafana`
(Grafana en `:3000`). Para aislar el fuzzer: `ISOLATION_RUNTIME=gvisor` (requiere
`runsc` instalado en el host).

### Local (solo Semgrep + reporte)

```bash
pip install -r requirements.txt semgrep
python main.py <target> --semgrep-config scripts/semgrep_cpp.yaml --no-joern --no-fuzzer
```

## CLI

```bash
python main.py scan <target> [--semgrep-config ...] [--no-joern] [--no-fuzzer] [--json]
python main.py targets list --platform hackerone --query github
python main.py targets search github.com
python main.py targets chaos --program Aiven
python main.py targets chaos --list
```

## Variables de entorno

| Variable | Default | Uso |
|---|---|---|
| `OLLAMA_MODEL` / `OLLAMA_BASE_URL` | `qwen2.5-coder` / `localhost:11434` | LLM |
| `OLLAMA_EMBED_MODEL` | `nomic-embed-text` | embeddings |
| `PGVECTOR_CONNECTION` | (vacío) | pgvector (memory/vectordb) |
| `REDIS_URL` | `redis://localhost:6379/0` | cola de eventos |
| `OTEL_ENABLED` / `OTEL_EXPORTER_OTLP_ENDPOINT` | `0` / `localhost:4317` | telemetría |
| `ISOLATION_RUNTIME` | `none` | `none`\|`docker`\|`gvisor` |
| `SOCKS5_PROXIES` | (vacío) | lista CSV de proxies para evasion |
| `FUZZ_TIME_LIMIT` / `FUZZ_ARGS` | `60` / `""` | fuzzing |
| `DEDUP_WINDOW_SECONDS` | `86400` | ventana de dedup |
| `SPECTRE_RECURSION_LIMIT` | `25` | límite del grafo cíclico |

## Fuzzing dirigido por SAST

`fuzzer_node` genera un diccionario AFL (`-x`) a partir de las fuentes/sumideros
de Semgrep/Joern vía `seedgen.findings_to_tokens()`. Para librerías con harnesses
OSS-Fuzz:

```bash
python -m agents.fuzzer_node /src --harness fuzzing/file_fuzzer.cc \
  --extra-source build/libheif/libheif.a --extra-flag -I./libheif \
  --fuzz-args "@@" --time-limit 300
```

## Pruebas

```bash
python -m pytest                 # unit (74 tests)
pytest --run-integration         # + Redis/pgvector (requiere docker compose up -d redis db)
```

## Seguridad de la propia infraestructura

- El fuzzing ejecuta **código no confiable**: úsalo con `ISOLATION_RUNTIME=gvisor`
  o `firecracker` (ver `agents/isolation.py`). Nunca en el host desnudo.
- La dedup (`agents/dedup.py`) evita re-analizar el mismo bug; la cola
  (`agents/events.py`) amortigua ráfagas de crashes ante la API del LLM.
- Todos los nodos son **fail-open**: un fallo de tooling devuelve estado vacío y
  el grafo continúa; ningún nodo propaga excepciones.

## Convenciones del código

- Cada nodo expone `*_node(state) -> dict` para LangGraph y una función core
  testable (`run_*`), con manejo robusto de subprocesos (jerarquía de excepciones
  por nodo + `except OSError` para AppLocker/WinError + red de seguridad).
- Las dependencias pesadas (`redis`, `asyncpg`, `tree_sitter`, `opentelemetry`,
  `langchain_*`) se importan de forma **perezosa** y degradan a no-op.
- Esquemas en `agents/state.py` (Pydantic + `SpectreState` TypedDict con
  reducers `operator.add`).

# SAP Commerce Cloud log analyzer

Triage SAP Commerce Cloud (CCv2) incidents from log files exported out of Dynatrace. The tool turns
thousands of log lines into a short list of distinct issues, explains the likely root cause of each
with Claude, and recommends what to do next.

Deterministic code does the heavy lifting first, so the LLM only sees a compact, redacted summary:

1. **Ingest** a Dynatrace export: Logs viewer CSV, a Grail/DQL `fetch logs` JSON result, a plain
   JSON array, or NDJSON. Stack traces that Dynatrace split into separate records are stitched back
   together.
2. **Normalize** each line into a typed record. Both the CCv2 log4j2 JSON layout and the classic
   `LEVEL [thread] [logger] message` pattern are understood. The CCv2 aspect (`api`, `backoffice`,
   `backgroundprocessing`, ...) is derived from the pod name.
3. **Redact** personal data and secrets (emails, bearer tokens, JWTs, passwords, URL credentials,
   session ids, card numbers, IPs). Redaction always runs, before anything else sees the text.
4. **Classify** against a catalogue of ~27 known SAP Commerce failure signatures: Hikari pool
   exhaustion, FlexibleSearch and SQL errors, OOM and GC pauses, Solr indexing and queries, CronJobs,
   ImpEx, cloud hot folders, Integration API and OData, OCC and OAuth, Spring context failures,
   cluster messaging, rule engine, business processes, media storage and more.
5. **Cluster** events that differ only in variable parts (PKs, ids, numbers, timestamps) and track
   count, first and last seen, aspects, pods, representative samples and application stack frames.
6. **Analyse** the clusters with Claude using structured outputs: root cause, affected component,
   severity, confidence, recommended actions and evidence. Large exports are analysed in batches and
   then summarised (map-reduce).
7. **Report** as Markdown, JSON or a self-contained HTML page.

## Quickstart

Requires Python 3.12+.

```bash
pip install -e ".[dev]"
export ANTHROPIC_API_KEY=...        # or: ant auth login

# Rules and clustering only: nothing leaves your machine
sapcx-log-analyzer analyze export.csv --no-llm

# See exactly what would be sent to the model, without sending it
sapcx-log-analyzer analyze export.csv --dry-run

# Full analysis, written as HTML
sapcx-log-analyzer analyze export.csv -f html -o reports/incident.html

# List the classification rules in the order they apply
sapcx-log-analyzer rules
```

Exit codes: `0` success, `2` unreadable or invalid input, `3` the LLM call failed (re-run with
`--no-llm` for a rules-only report).

## Asking questions about a transaction

The report answers "what is broken overall". To ask about one transaction, order or request, load
an export into a chat:

```bash
# Chat in the terminal
sapcx-log-analyzer ask export.json

# One question, then exit (handy in scripts and tickets)
sapcx-log-analyzer ask export.json -q "What went wrong with transaction tx-243232?"

# The same chat as a local web page with clickable evidence
sapcx-log-analyzer serve export.json          # then open http://localhost:8765/
```

Claude investigates with a handful of read-only lookups over the loaded export and shows each one as
it runs:

- **find an identifier**: every line that mentions a transaction id, order or cart code, trace id,
  correlation or request id, plus the lines that share its trace or correlation id. Typos and
  partial ids get suggestions.
- **context**: the lines just before and after a line on the same thread, pod or across the
  environment. This matters because the line that fails often does not carry the id.
- **search** by text, level, pod, aspect and time window, and **open** one record in full.
- **known issues**: which rule-catalogue problems (pool exhaustion, Solr, OOM and so on) were active
  at that moment, so a victim can be told apart from the cause.

The answer gives a short verdict, a timeline citing log lines as `#ref`, the root cause, next steps
and a confidence level. Follow-up questions keep the context. In the terminal, `/record 42` prints a
line locally, `/new` starts over and `/exit` quits. In the web page, click a `#ref` to see the line
and its surroundings.

Identifiers come from Dynatrace attributes (`trace_id`, `span_id`, `x-request-id` and similar), CCv2
MDC values in the log4j2 JSON layout (`contextMap`) and from the message text (`orderCode=...`,
`cart 00012345`, `tx-243232`, UUIDs, 32-character trace ids). Session ids are masked as stable
`<SESSION#1a2b3c4d>` tokens, so lines of the same session can still be followed without exposing it.

The web server is meant for your own machine. It listens on `127.0.0.1` only, has no login, accepts
JSON requests only and rejects requests for any other host name. If you bind it elsewhere with
`--host`, anyone who can reach the port can read the logs and spend API credits; pass the address
users will type with `--allow-host`.

## Exporting logs from Dynatrace

Either of these works:

- **Logs viewer:** filter on your CCv2 environment (for example by `k8s.namespace.name` or the cloud
  application), pick the time window of the incident, then export as CSV. Keep the `timestamp`,
  `status`/`loglevel`, `content` and `k8s.pod.name` columns.
- **Notebook or DQL:** run a query such as the one below and download the result as JSON.

```
fetch logs, from: -2h
| filter k8s.namespace.name == "<your-namespace>"
| filter loglevel != "DEBUG"
| fields timestamp, loglevel, content, k8s.pod.name, k8s.container.name
```

Including `INFO` lines is fine: they are dropped unless a rule needs them (GC pauses, for example).

## Configuration

Settings come from, highest precedence first: CLI flags, `SAPCX_LA_*` environment variables, a YAML
file passed with `--config`, and built-in defaults. See [`examples/config.yaml`](examples/config.yaml).

| Setting | Env var | Default | Purpose |
|---|---|---|---|
| `model` | `SAPCX_LA_MODEL` | `claude-opus-5-5` | Claude model id |
| `effort` | `SAPCX_LA_EFFORT` | `high` | `low` to `max`; lower is cheaper and faster |
| `max_output_tokens` | `SAPCX_LA_MAX_OUTPUT_TOKENS` | `16000` | Output cap per request |
| `use_refusal_fallback` | `SAPCX_LA_USE_REFUSAL_FALLBACK` | `true` | Retry a declined request on Anthropic's recommended fallback model |
| `min_level` | `SAPCX_LA_MIN_LEVEL` | `WARN` | Lowest log level analysed |
| `max_chars_per_batch` | `SAPCX_LA_MAX_CHARS_PER_BATCH` | `80000` | Batch size for map-reduce (about 4 chars per token) |
| `max_clusters_for_llm` | `SAPCX_LA_MAX_CLUSTERS_FOR_LLM` | `150` | Only the most severe clusters are sent |
| `samples_per_cluster` | `SAPCX_LA_SAMPLES_PER_CLUSTER` | `3` | Representative events kept per cluster |
| `timeline_bucket_minutes` | `SAPCX_LA_TIMELINE_BUCKET_MINUTES` | `5` | Timeline granularity |
| `ask_effort` | `SAPCX_LA_ASK_EFFORT` | `medium` | Effort for `ask` and `serve`; `high` digs deeper but answers slower |
| `ask_max_tool_rounds` | `SAPCX_LA_ASK_MAX_TOOL_ROUNDS` | `12` | Lookup rounds per question before Claude must answer |
| `ask_max_tool_result_chars` | `SAPCX_LA_ASK_MAX_TOOL_RESULT_CHARS` | `24000` | Cap on one lookup result sent to the model |
| `extra_rules_file` | `SAPCX_LA_EXTRA_RULES_FILE` | none | Project rules, checked before the built-in ones |
| `extra_redaction_patterns` | | none | Extra regexes to mask, such as customer numbers |

The API key is never read from these settings. The Anthropic SDK reads `ANTHROPIC_API_KEY` (or an
`ant auth login` profile) itself, so keep it in your secret store, not in the repository.

## Adding a rule

Built-in rules live in
[`src/sapcx_log_analyzer/classify/rules/sapcx_rules.yaml`](src/sapcx_log_analyzer/classify/rules/sapcx_rules.yaml).
Rules are checked in order and the first match wins, so put specific rules above generic ones. For
project-specific signatures, write a separate file (see
[`examples/project_rules.yaml`](examples/project_rules.yaml)) and point `extra_rules_file` at it.
Add a case to `tests/test_classify.py` for every new rule.

## Data protection

- Redaction runs on every record before classification, clustering, reporting or any LLM call.
- `analyze` sends only cluster summaries and a few redacted samples, never the raw export.
- `ask` and `serve` send a summary of the export (time range, pods, counts) and the redacted log
  lines that Claude looks up for a question (each lookup is
  capped), plus your question, which is redacted the same way. The export itself stays local.
- `--no-llm` keeps everything local. `--dry-run` prints the exact request bodies for review.
- Review the default patterns in `redact/redactor.py` against your own data before first use and add
  project-specific ones via `extra_redaction_patterns`.

## Development

```bash
pip install -e ".[dev]"
pre-commit install
ruff check src tests && ruff format --check src tests
mypy src tests
pytest --cov
```

Tests never call the real API: the LLM provider is an interface, and tests use a fake one. To run the
opt-in smoke test against the real model, which sends only the synthetic fixture data:

```bash
SAPCX_LA_LIVE_TESTS=1 ANTHROPIC_API_KEY=... pytest -m live
```

Test fixtures in `tests/fixtures` are synthetic and generated by
`python tests/fixtures/make_fixtures.py`.

### Layout

```
src/sapcx_log_analyzer/
  cli.py          Typer CLI: analyze, ask, serve, rules
  config.py       Settings (pydantic-settings)
  models.py       LogRecord, Cluster, Finding, Report
  pipeline.py     Wires the stages together
  ingest/         Dynatrace CSV and JSON readers, format detection
  parse/          log4j2 JSON layout, pattern lines, stack traces, normalization
  redact/         PII and secret masking
  classify/       Rule engine and the SAP Commerce rule catalogue
  cluster/        Fingerprinting, aggregation, timeline
  llm/            Provider interface, Anthropic provider, prompts, map-reduce analyzer
  report/         Markdown, JSON and HTML rendering
  ask/            Interactive questions: searchable store, identifiers, tools, chat loop, web UI
```

## Not yet included

- Pulling logs directly from the Dynatrace API (the ingest layer is ready for another source).
- A web UI for the report itself (the `serve` chat covers questions; the JSON report is the stable
  contract for a report UI).
- Trend analysis across several runs.

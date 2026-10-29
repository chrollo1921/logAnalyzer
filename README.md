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

## Asking questions about the logs

The report answers "what is broken overall". To ask your own questions, about the export as a whole
or about one transaction, user, B2B account, session or API call, load an export into a chat:

```bash
# Chat in the terminal
sapcx-log-analyzer ask export.json

# One question, then exit (handy in scripts and tickets)
sapcx-log-analyzer ask export.json -q "What went wrong with transaction tx-243232?"

# A web chat: upload exports in the browser and ask questions about them
sapcx-log-analyzer serve                      # then open http://localhost:8765/
```

Questions it is built for:

- What were the main problems in this file? What happened just before the outage?
- Is checkout slower than usual at any point? Which endpoints fail most, and why?
- Is there anything about Solr, payments or the catalog sync?
- What went wrong with transaction tx-243232? Why did order 00012345 fail?
- What happened with account id 1234, and which APIs did they hit?
- Why did the order fail for user 23dsfd (or for jane.doe@example.com)?
- What is the reason for the failures of /cart/323232/getDelivery?
- What happened in session 74E4F046B991AE27C8E483476E53AEAC?

No export at hand? Generate a realistic, entirely synthetic one with planted incidents (a payment
timeout for user `23dsfd`, a carrier timeout on `/cart/323232/getDelivery`, a missing permission and
an order approval for B2B account `1234`, a database pool outage that follows a catalog sync and
rising pool warnings, a failed Solr CronJob, a pod restart, and 15 minutes of slow payments after the
payment provider fails over to another region):

```bash
sapcx-log-analyzer demo-export demo.json --size-mb 10
sapcx-log-analyzer serve                      # and upload demo.json in the browser
```

Claude investigates with a handful of read-only lookups over the loaded export and shows each one as
it runs:

- **find an identifier**: every line that mentions a transaction id, user or customer id, B2B
  account (unit) id, order or cart code, trace id, correlation or request id, session or email, plus
  the lines that share its trace or correlation id. Typos and partial ids get suggestions.
- **API calls**: the HTTP requests of a user, account, session, cart or order, or of one endpoint,
  with status and duration, grouped by endpoint, for example
  `GET /occ/v2/electronics/cart/{id}/getDelivery: 3 (504x3, max 10050 ms)`.
  Requests come from access log lines and from application lines such as `Request POST ... failed
  with 500`; access log lines are tied to a user through the trace id they share with the
  application log.
- **context**: the lines just before and after a line on the same thread, pod or across the
  environment. This matters because the line that fails often does not carry the id.
- **search** by text, level, pod, aspect and time window, and **open** one record in full.
- **known issues**: which rule-catalogue problems (pool exhaustion, Solr, OOM and so on) were active
  at that moment, so a victim can be told apart from the cause.

For questions about the whole export, the file is profiled once when it loads, and Claude gets the
profile with every conversation:

- **message patterns**: lines with the same logger and message apart from ids and numbers are one
  pattern (`P17`), so 15,000 lines become a few dozen to a few hundred patterns Claude can read as a
  catalogue. Access log lines become one pattern per endpoint and status class.
- **candidate incidents**: minutes in which errors, 5xx responses or p95 latency are far above the
  file's own median (median plus four median absolute deviations, with minimum margins), with the
  patterns that appeared or rose in the 15 minutes before each one, and the lifecycle events in
  those minutes.
- **latency shifts**: endpoints that were much slower than their own norm for a while, outside
  outages, such as payment calls after a provider failover.
- **lifecycle events**: deployments, pod restarts, CronJobs, catalog syncs, Solr indexing, cache
  clears and integration failovers, recognized by `classify/rules/events.yaml`.
- the main problem patterns, and the busiest, slowest and most failing endpoints.

Claude then investigates with four more tools: a **timeline** of log lines, requests, 5xx responses
or latency per time bucket, split by pattern, level, pod, endpoint or status; **compare windows**,
which lists the patterns or endpoints that appeared, rose, fell or stopped in one window against
another, for "what changed before the outage"; **endpoint stats** with p50, p95 and p99 latency and
error rates, optionally against a baseline window, for "is checkout slower than usual"; and the
**pattern catalogue**, filtered by level, text, logger, aspect or time. Search can also group its
matches by pattern. Every number comes from code; Claude chooses what to look at, explains it and
cites lines. "Usual" can only mean another period of the same export, and the answer says which.

The answer gives a short verdict, a timeline citing log lines as `#ref`, the root cause, next steps
and a confidence level. When the question is about an id, user or time the export does not cover,
the answer says so first and gives the export's time range instead of answering from a similar id
or a different window; a question unrelated to the logs gets a one-line pointer back to what the
chat can answer. Follow-up questions keep the context. In the terminal, `/record 42` prints a
line locally, `/new` starts over and `/exit` quits. In the web chat, click a `#ref` to see the line
and its surroundings.

Identifiers come from Dynatrace attributes (`trace_id`, `span_id`, `x-request-id` and similar), CCv2
MDC values in the log4j2 JSON layout (`contextMap`, for example `userId`, `b2bUnitId`, `sessionId`)
and from the message text (`orderCode=...`, `cart 00012345`, `customerId 23dsfd`, `tx-243232`,
UUIDs, 32-character trace ids). Session ids and email addresses are masked as stable
`<SESSION#1a2b3c4d>` and `<EMAIL#9f8e7d6c>` tokens, so lines of the same session or customer can
still be followed without exposing them. Your question is masked the same way, so asking about
`jane.doe@example.com` or a raw session id finds its token.

### Large exports

A 10 MB export (about 15,000 lines) loads and is profiled in about 2 seconds and uses under 100 MB
of memory; each lookup then takes milliseconds. A 100 MB export takes about 25 seconds and 600 MB. The file is never sent to Claude as a whole (10 MB of logs would be
about 2.5 million tokens, far more than a model can read, and expensive). Claude sees an overview
and profile of the export (about 2,000 tokens) and only the lines its lookups return, each lookup capped at
`ask_max_tool_result_chars`, so a typical question costs a few tens of thousands of tokens whatever
the file size. Exports of 100 MB and more work the same way but take longer to load; narrow the
Dynatrace query to the incident window where you can.

## The web chat for a team

`sapcx-log-analyzer serve` runs a web app in which people upload a Dynatrace export (drag and drop,
JSON, NDJSON or CSV) and then chat about it. Several people can use one server at the same time:

- Everyone has their own files and conversations. A file is visible only to the person who
  uploaded it until they tick **Share**; then everyone signed in can ask about it, each in their own
  conversation.
- Uploads are parsed and redacted in the background (a 10 MB file takes 2 to 3 seconds) and the
  raw file is deleted as soon as it has been read. Only the redacted copy is kept, in memory.
- Files nobody has used for `server_upload_idle_hours` are removed, and a restart clears everything.
- At most `server_max_concurrent_questions` questions are answered at once, so a busy team cannot
  exhaust the Anthropic rate limit; the others wait their turn and see that they are waiting.
- The Anthropic API key lives on the server only. People using the chat do not need one.

On your own machine it needs no sign-in and listens on `127.0.0.1`. For a team, run it on a server
or in a container behind your HTTPS reverse proxy and pick a sign-in mode with `--auth` or
`SAPCX_LA_SERVER_AUTH`:

| Mode | Who can sign in | Use it when |
|---|---|---|
| `none` | Anyone who can reach the server (allowed on `127.0.0.1` only) | Trying it on your laptop |
| `token` | Anyone with the team access key in `SAPCX_LA_SERVER_ACCESS_TOKEN`, who also enters a name | A small team without single sign-on |
| `header` | Whoever your SSO proxy (oauth2-proxy, an identity-aware proxy, an API gateway) signed in; the app reads their email from `X-Forwarded-Email` (`server_user_header`) | Company login in front of the app; make sure only the proxy can reach it |

```bash
# A team server with an access key
export ANTHROPIC_API_KEY=...
export SAPCX_LA_SERVER_ACCESS_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(24))')"
sapcx-log-analyzer serve --host 0.0.0.0 --auth token --allow-host logs.example.com

# The same in a container (see Dockerfile)
docker build -t sapcx-log-analyzer .
docker run -p 8765:8765 -e ANTHROPIC_API_KEY -e SAPCX_LA_SERVER_ACCESS_TOKEN \
  -e SAPCX_LA_SERVER_ALLOWED_HOSTS='["logs.example.com"]' sapcx-log-analyzer
```

The server refuses to start without sign-in on any address but `127.0.0.1`, and in `token` mode
without a key of at least 16 characters. It serves only the host names you list with
`--allow-host` or `server_allowed_hosts` (DNS rebinding), requires an `X-Requested-With` header on
every request that changes something and uses `SameSite=Strict` session cookies (cross-site
requests), and limits the upload size. Sign-ins, uploads, shares and questions are logged with the
user's name, never with the question's text. `/healthz` is there for container health checks.

Run one server process: files and conversations live in its memory, and one process serves many
people because answers wait on Claude, not on the CPU. Plan about 7 times the export size in memory
per loaded file (a 10 MB export takes about 70 MB), so the defaults of 30 files of up to 100 MB fit
in a few GB. Keep a reverse proxy that streams responses (for nginx, the app sends
`X-Accel-Buffering: no`) so progress shows while Claude investigates.

## Exporting logs from Dynatrace

Either of these works:

- **Logs viewer:** filter on your CCv2 environment (for example by `k8s.namespace.name` or the cloud
  application), pick the time window of the incident, then export as CSV. Keep the `timestamp`,
  `status`/`loglevel`, `content` and `k8s.pod.name` columns. Renamed columns such as
  `Log message`, `Log Level` or `@timestamp` are recognised too, as are comma, semicolon, tab and
  pipe delimiters and UTF-8, UTF-16 (Excel "Unicode text") or Windows-1252 files. A CSV with no
  message column is rejected with the columns it has.
- **Notebook or DQL:** run a query such as the one below and download the result as JSON.

```
fetch logs, from: -2h
| filter k8s.namespace.name == "<your-namespace>"
| filter loglevel != "DEBUG"
| fields timestamp, loglevel, content, k8s.pod.name, k8s.container.name
```

Including `INFO` lines is fine: they are dropped unless a rule needs them (GC pauses, for example).

For `ask` and `serve`, export more of each request so a user, session or API call can be followed:
keep `INFO` (the line that names the user or cart is usually INFO), keep the Tomcat or ingress
access log lines, and add the trace ids that tie an access log line to the application lines of
the same request.

```
fetch logs, from: "2026-10-20T08:00:00Z", to: "2026-10-20T10:00:00Z"
| filter k8s.namespace.name == "<your-namespace>"
| fields timestamp, loglevel, content, k8s.pod.name, k8s.container.name, trace_id, span_id
```

If your project logs the user, B2B unit or session in the MDC (log4j2 `contextMap`), every line of a
request can be found by that id; if not, the trace id still links them.

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
| `server_auth` | `SAPCX_LA_SERVER_AUTH` | `none` | Web chat sign-in: `none`, `token` or `header` |
| `server_access_token` | `SAPCX_LA_SERVER_ACCESS_TOKEN` | none | Team access key for `token`; keep it in your secret store |
| `server_user_header` | `SAPCX_LA_SERVER_USER_HEADER` | `X-Forwarded-Email` | Header your SSO proxy sets, for `header` |
| `server_allowed_hosts` | `SAPCX_LA_SERVER_ALLOWED_HOSTS` | none | Host names people use in the browser, as a JSON list in the env var |
| `server_max_upload_mb` | `SAPCX_LA_SERVER_MAX_UPLOAD_MB` | `100` | Largest upload |
| `server_max_uploads_per_user` | `SAPCX_LA_SERVER_MAX_UPLOADS_PER_USER` | `5` | Files one person can have loaded |
| `server_max_uploads` | `SAPCX_LA_SERVER_MAX_UPLOADS` | `30` | Files loaded on the server in total |
| `server_upload_idle_hours` | `SAPCX_LA_SERVER_UPLOAD_IDLE_HOURS` | `8` | Unused files are removed after this |
| `server_session_hours` | `SAPCX_LA_SERVER_SESSION_HOURS` | `12` | How long a sign-in lasts |
| `server_max_concurrent_questions` | `SAPCX_LA_SERVER_MAX_CONCURRENT_QUESTIONS` | `4` | Questions answered at once; the rest wait |
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
- Session ids and email addresses become `<SESSION#...>` and `<EMAIL#...>` tokens: a short hash
  with a random salt that changes on every run, so a token cannot be reversed or matched against
  another run.
- `analyze` sends only cluster summaries and a few redacted samples, never the raw export.
- `ask` and `serve` send a summary of the export (time range, pods, counts) and the redacted log
  lines that Claude looks up for a question (each lookup is
  capped), plus your question, which is redacted the same way. The export itself never goes to
  Claude.
- The web chat deletes an uploaded file as soon as it has been parsed and keeps only the redacted
  copy in memory, visible to the uploader and, if they share it, to everyone signed in.
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
opt-in tests against the real model, which send only synthetic data: a smoke test of the report and
the chat, and a check set of open questions about the demo export ("what were the main problems?",
"what happened just before the outage?", "is checkout slower than usual?", an unrelated question)
whose answers must name the planted causes. Run it when the prompt or the tools change:

```bash
SAPCX_LA_LIVE_TESTS=1 ANTHROPIC_API_KEY=... pytest -m live
```

Test fixtures in `tests/fixtures` are synthetic and generated by
`python tests/fixtures/make_fixtures.py`.

### Layout

```
src/sapcx_log_analyzer/
  cli.py          Typer CLI: analyze, ask, serve, rules, demo-export
  demo.py         Synthetic SAP Commerce Cloud export for trying the tool
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
  ask/            Interactive questions: searchable store, identifiers, export profile and
                  digest, lookup and analysis tools, chat loop
  server/         Web chat: uploads, sign-in, per-user files and conversations, page
```

## Not yet included

- Pulling logs directly from the Dynatrace API (the ingest layer is ready for another source).
- A web UI for the report itself (the `serve` chat covers questions; the JSON report is the stable
  contract for a report UI).
- Keeping uploads across restarts or sharing them between several server processes (state is in
  memory by design, so the raw logs are never stored).
- Trend analysis across several runs.

"""Command line interface."""

from __future__ import annotations

import logging
import socket
from pathlib import Path
from typing import Annotated

import typer

from sapcx_log_analyzer import __version__
from sapcx_log_analyzer.ask.store import LogStore
from sapcx_log_analyzer.classify import RuleEngine
from sapcx_log_analyzer.config import Effort, Settings, load_settings
from sapcx_log_analyzer.demo import write_demo_export
from sapcx_log_analyzer.ingest import ExportFormat
from sapcx_log_analyzer.ingest.dynatrace_json import ExportFormatError
from sapcx_log_analyzer.llm import ChatProvider, LLMAnalyzer, LLMError, LLMProvider
from sapcx_log_analyzer.models import LogLevel
from sapcx_log_analyzer.pipeline import prepare
from sapcx_log_analyzer.report import OutputFormat, render

EXIT_INPUT_ERROR = 2
EXIT_LLM_ERROR = 3

app = typer.Typer(
    help="Triage SAP Commerce Cloud logs exported from Dynatrace.",
    no_args_is_help=True,
    add_completion=False,
)


def build_provider(settings: Settings) -> LLMProvider:
    """Factory for the LLM backend; tests replace this."""
    from sapcx_log_analyzer.llm.anthropic_provider import AnthropicProvider

    return AnthropicProvider(settings)


def build_chat_provider(settings: Settings) -> ChatProvider:
    """Factory for the chat backend used by `ask` and `serve`; tests replace this."""
    from sapcx_log_analyzer.llm.anthropic_provider import AnthropicProvider

    return AnthropicProvider(settings)


def _version(value: bool) -> None:
    if value:
        typer.echo(__version__)
        raise typer.Exit()


@app.callback()
def main(
    verbose: Annotated[
        bool, typer.Option("--verbose", "-v", help="Log progress to stderr.")
    ] = False,
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )


@app.command()
def analyze(
    export_file: Annotated[
        Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="Dynatrace export.")
    ],
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report here, not stdout.")
    ] = None,
    fmt: Annotated[OutputFormat, typer.Option("--format", "-f", help="Report format.")] = (
        OutputFormat.MARKDOWN
    ),
    input_format: Annotated[
        ExportFormat | None, typer.Option("--input-format", help="Override format detection.")
    ] = None,
    config: Annotated[
        Path | None, typer.Option("--config", "-c", exists=True, dir_okay=False, help="YAML.")
    ] = None,
    no_llm: Annotated[
        bool,
        typer.Option("--no-llm", help="Rules and clustering only; nothing leaves the machine."),
    ] = False,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Print exactly what would be sent to the model.")
    ] = False,
    model: Annotated[str | None, typer.Option(help="Claude model id.")] = None,
    effort: Annotated[str | None, typer.Option(help="low, medium, high, xhigh or max.")] = None,
    min_level: Annotated[
        LogLevel | None, typer.Option("--min-level", help="Lowest level to analyse.")
    ] = None,
) -> None:
    """Analyse a Dynatrace log export and write an incident report."""
    try:
        settings = load_settings(config, model=model, effort=_effort(effort), min_level=min_level)
        prepared = prepare(export_file, settings, input_format)
    except (ExportFormatError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR) from exc
    report = prepared.report

    if dry_run:
        prompts = LLMAnalyzer(_NoCallProvider(settings.model), settings).build_prompts(
            report.clusters, report.metadata
        )
        for index, prompt in enumerate(prompts, start=1):
            typer.echo(f"===== request {index} of {len(prompts)} ({len(prompt)} chars) =====")
            typer.echo(prompt)
        return

    if not no_llm:
        try:
            provider = build_provider(settings)
            report.analysis = LLMAnalyzer(provider, settings).analyze(
                report.clusters, report.metadata
            )
        except LLMError as exc:
            typer.echo(f"LLM analysis failed: {exc}", err=True)
            typer.echo("Re-run with --no-llm for a rules-only report.", err=True)
            raise typer.Exit(EXIT_LLM_ERROR) from exc
        report.metadata.llm_used = True
        report.metadata.model = provider.model_name

    text = render(report, fmt)
    if output is None:
        typer.echo(text, nl=False)
    else:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
        typer.echo(f"Wrote {fmt.value} report to {output}", err=True)


ExportArg = Annotated[
    Path, typer.Argument(exists=True, dir_okay=False, readable=True, help="Dynatrace export.")
]
InputFormatOpt = Annotated[
    ExportFormat | None, typer.Option("--input-format", help="Override format detection.")
]
ConfigOpt = Annotated[
    Path | None, typer.Option("--config", "-c", exists=True, dir_okay=False, help="YAML.")
]
ModelOpt = Annotated[str | None, typer.Option(help="Claude model id.")]
EffortOpt = Annotated[
    str | None, typer.Option(help="low, medium, high, xhigh or max (default medium).")
]


def _load_store(
    export_file: Path,
    config: Path | None,
    input_format: ExportFormat | None,
    model: str | None,
    effort: str | None,
) -> tuple[Settings, LogStore]:
    try:
        settings = load_settings(config, model=model, ask_effort=_effort(effort))
        typer.echo(f"Loading {export_file.name} …", err=True)
        store = LogStore.load(export_file, settings, input_format)
    except (ExportFormatError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR) from exc
    overview = store.overview()
    typer.echo(
        f"Loaded {overview['records']} records from {overview['time_range_start']} to "
        f"{overview['time_range_end']}, {overview['known_issue_clusters']} known issue patterns.",
        err=True,
    )
    return settings, store


@app.command()
def ask(
    export_file: ExportArg,
    question: Annotated[
        str | None,
        typer.Option("--question", "-q", help="Ask one question and exit, instead of chatting."),
    ] = None,
    input_format: InputFormatOpt = None,
    config: ConfigOpt = None,
    model: ModelOpt = None,
    effort: EffortOpt = None,
    show_steps: Annotated[
        bool, typer.Option("--show-steps/--hide-steps", help="Print each log lookup.")
    ] = True,
) -> None:
    """Chat about an export: ask what went wrong with a transaction, order or request."""
    from sapcx_log_analyzer.ask import AskSession, ToolStep

    settings, store = _load_store(export_file, config, input_format, model, effort)
    try:
        session = AskSession(store, build_chat_provider(settings), settings)
    except LLMError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_LLM_ERROR) from exc

    def on_step(step: ToolStep) -> None:
        if show_steps:
            typer.secho(f"  - {step.summary}", err=True, dim=True)

    def answer(text: str) -> bool:
        try:
            result = session.ask(text, on_step=on_step)
        except LLMError as exc:
            typer.echo(f"Claude could not answer: {exc}", err=True)
            return False
        typer.echo("")
        typer.echo(result.text)
        typer.echo("")
        return True

    if question is not None:
        if not answer(question):
            raise typer.Exit(EXIT_LLM_ERROR)
        return

    examples = store.sample_identifiers()
    typer.echo(
        "Ask about the whole file (what were the main problems? is checkout slower than "
        "usual?) or about one transaction, user, order or trace id"
        + (f", for example: what went wrong with {examples[0]}?" if examples else ".")
        + "\nCommands: /record <ref> shows a log line, /new starts over, /exit quits.",
        err=True,
    )
    while True:
        try:
            text = input("ask> ").strip()
        except (EOFError, KeyboardInterrupt):
            typer.echo("", err=True)
            return
        if not text:
            continue
        if text in {"/exit", "/quit", "exit", "quit"}:
            return
        if text == "/new":
            session.reset()
            typer.echo("Started a new conversation.", err=True)
            continue
        if text.startswith("/record"):
            _print_record(store, text.removeprefix("/record").strip().lstrip("#"))
            continue
        answer(text)


def _print_record(store: LogStore, ref_text: str) -> None:
    from sapcx_log_analyzer.ask.tools import format_record

    try:
        typer.echo(format_record(store, int(ref_text), full=True))
    except (ValueError, KeyError):
        typer.echo(f"No record {ref_text!r}; use /record <number>.", err=True)


@app.command()
def serve(
    export_file: Annotated[
        Path | None,
        typer.Argument(
            exists=True,
            dir_okay=False,
            readable=True,
            help="Optional export to load at start, shared with everyone.",
        ),
    ] = None,
    host: Annotated[str, typer.Option(help="Address to listen on.")] = "127.0.0.1",
    port: Annotated[int, typer.Option(help="Port to listen on; 0 picks a free one.")] = 8765,
    allow_host: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-host",
            help="Host name people type in the browser, e.g. logs.example.com. Repeatable.",
        ),
    ] = None,
    auth: Annotated[
        str | None,
        typer.Option(help="Sign-in: none, token (team access key) or header (company SSO)."),
    ] = None,
    input_format: InputFormatOpt = None,
    config: ConfigOpt = None,
    model: ModelOpt = None,
    effort: EffortOpt = None,
) -> None:
    """Run the web chat: upload exports in the browser and ask questions, several people at once."""
    import uvicorn

    from sapcx_log_analyzer.server import create_app, is_loopback

    if auth is not None and auth not in ("none", "token", "header"):
        raise typer.BadParameter("auth must be none, token or header")
    try:
        settings = load_settings(config, model=model, ask_effort=_effort(effort), server_auth=auth)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR) from exc
    problem = _server_problem(settings, host)
    if problem:
        typer.echo(f"Error: {problem}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR)
    try:
        provider = build_chat_provider(settings)
    except LLMError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_LLM_ERROR) from exc
    try:
        if export_file is not None:
            typer.echo(f"Loading {export_file.name} …", err=True)
        web_app = create_app(
            settings,
            provider,
            preload=export_file,
            preload_format=input_format,
            allowed_hosts=allow_host or [],
        )
    except (ExportFormatError, ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR) from exc
    try:
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        sock = socket.create_server((host, port), family=family)
    except OSError as exc:
        typer.echo(f"Error: cannot listen on {host}:{port}: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR) from exc
    logging.getLogger("sapcx_log_analyzer").setLevel(logging.INFO)  # sign-ins and uploads
    if not is_loopback(host) and not (allow_host or settings.server_allowed_hosts):
        typer.secho(
            "Note: browsers can only use localhost until you add the server's name with "
            "--allow-host or SAPCX_LA_SERVER_ALLOWED_HOSTS.",
            err=True,
            fg="yellow",
        )
    # Listening on every interface includes this machine, so localhost works.
    shown = "localhost" if is_loopback(host) or host in ("0.0.0.0", "::") else host  # noqa: S104
    sign_in = {"none": "no sign-in", "token": "team access key", "header": "company login"}
    typer.echo(
        f"Open http://{shown}:{sock.getsockname()[1]}/  ({sign_in[settings.server_auth]}; "
        "Ctrl+C to stop)",
        err=True,
    )
    server = uvicorn.Server(uvicorn.Config(web_app, log_level="info", proxy_headers=True))
    server.run(sockets=[sock])


def _server_problem(settings: Settings, host: str) -> str | None:
    """Why the server must not start with these settings, if it must not."""
    from sapcx_log_analyzer.server import is_loopback
    from sapcx_log_analyzer.server.auth import MIN_TOKEN_LENGTH

    if settings.server_auth == "none" and not is_loopback(host):
        return (
            f"without sign-in, anyone who can reach {host} could read the logs. Use --auth "
            "token with SAPCX_LA_SERVER_ACCESS_TOKEN, or --auth header behind your company "
            "login, or listen on 127.0.0.1."
        )
    token = settings.server_access_token
    if settings.server_auth == "token" and (
        token is None or len(token.get_secret_value()) < MIN_TOKEN_LENGTH
    ):
        return (
            f"set SAPCX_LA_SERVER_ACCESS_TOKEN to a random key of at least {MIN_TOKEN_LENGTH} "
            'characters, for example the output of: python -c "import secrets; '
            'print(secrets.token_urlsafe(24))"'
        )
    return None


@app.command("rules")
def list_rules(
    rules_file: Annotated[
        Path | None,
        typer.Option("--rules-file", exists=True, dir_okay=False, help="Extra project rules."),
    ] = None,
) -> None:
    """List the classification rules in the order they are applied."""
    try:
        engine = RuleEngine.default(rules_file)
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(EXIT_INPUT_ERROR) from exc
    for rule in engine.rules:
        typer.echo(f"{rule.id:32} {rule.severity.value:8} {rule.component}")


@app.command("demo-export")
def demo_export(
    output: Annotated[Path, typer.Argument(dir_okay=False, help="Where to write the export.")],
    size_mb: Annotated[
        float, typer.Option("--size-mb", min=0.05, max=500, help="Approximate file size.")
    ] = 10.0,
    seed: Annotated[int, typer.Option(help="Change it for different random traffic.")] = 7,
) -> None:
    """Write a synthetic SAP Commerce Cloud export with planted incidents, to try the tool."""
    count = write_demo_export(output, size_mb=size_mb, seed=seed)
    typer.echo(f"Wrote {count} records ({output.stat().st_size / 1_048_576:.1f} MB) to {output}")
    typer.echo(
        "Try: what happened with account 1234 and which APIs did they hit? / why did the "
        "order fail for user 23dsfd? / why did /cart/323232/getDelivery fail?"
    )


def _effort(value: str | None) -> Effort | None:
    allowed = ("low", "medium", "high", "xhigh", "max")
    if value is None:
        return None
    if value not in allowed:
        raise typer.BadParameter(f"effort must be one of {', '.join(allowed)}")
    return value  # type: ignore[return-value]


class _NoCallProvider:
    """Stands in for a provider when only the prompts are needed."""

    def __init__(self, model: str) -> None:
        self._model = model

    @property
    def model_name(self) -> str:
        return self._model

    def complete_json(
        self, *, system: str, prompt: str, schema: dict[str, object]
    ) -> dict[str, object]:
        raise AssertionError("dry run must not call the model")

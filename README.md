# Codex Run Inspector

Codex Run Inspector is a local observability and audit tool for OpenAI Codex CLI sessions. It wraps `codex exec --json`, stores the resulting event stream in SQLite, records git evidence before and after each run, and provides a Streamlit dashboard for inspecting commands, files, approvals, sandbox behavior, risks, and final outcomes.

It can also passively observe likely active Codex sessions that were not launched through `codex-inspector run`. Passive observations are labeled explicitly as partial or process-only so they are not confused with complete wrapped runs.

## Architecture

```text
codex-inspector run
  -> codex exec --json -C <repo> <prompt>
  -> JSONL normalizer + redaction
  -> SQLite storage
  -> analyzer and risk findings
  -> Streamlit dashboard
```

Core modules live in `codex_inspector/`:

- `runner.py` wraps Codex and records git snapshots.
- `observer.py` discovers likely active Codex processes and records process evidence.
- `tailer.py` incrementally ingests explicit JSON, JSONL, log, or transcript-like sources using durable cursors.
- `normalizer.py` maps Codex-like JSON events into a stable schema.
- `storage.py` owns SQLite tables for runs, events, commands, files, git snapshots, findings, and imports.
- `analyzer.py` computes metrics, quality summaries, and explainable risk findings.
- `dashboard.py` renders the Streamlit UI.
- `importer.py` imports JSONL, transcripts, and synthetic fixtures.

## Installation

This project is managed with `uv`. Install `uv`, then create or update the local environment from the lockfile:

```bash
uv sync --all-groups
```

For CLI-only use, `uv sync` is enough because the core package uses only the Python standard library. Use `uv sync --group dashboard` before dashboard work, or `uv sync --all-groups` for the full maintainer environment.

## Basic Usage

Initialize the local database:

```bash
uv run codex-inspector init
```

Run a real Codex task through the wrapper:

```bash
uv run codex-inspector run --repo . -- "Refactor the parser and add tests"
```

If Codex CLI is not installed, use fixture mode:

```bash
uv run codex-inspector import-fixtures
uv run codex-inspector dashboard
```

Import a saved JSONL event stream:

```bash
uv run codex-inspector import-jsonl ./run.jsonl
```

Best-effort transcript import accepts a file or directory:

```bash
uv run codex-inspector import-transcript ./codex-session/
```

List or inspect stored runs:

```bash
uv run codex-inspector list-runs
uv run codex-inspector show-run <run_id>
```

## Passive Observation

Use passive observation for Codex sessions started outside the wrapper, such as a Codex CLI session already running in another terminal.

Discover likely active Codex processes and candidate source files:

```bash
uv run codex-inspector discover
uv run codex-inspector discover --candidate-dir ./logs
uv run codex-inspector discover --candidate-dir ./logs --attach-candidates
```

Run one refresh cycle that discovers processes, tails known sources, scans process cwd/repo for sources, and optionally attaches candidate directories:

```bash
uv run codex-inspector observe --once
uv run codex-inspector observe --once --candidate-dir ./logs
uv run codex-inspector observe --once --idle-seconds 30
```

Keep observations fresh from a terminal or the dashboard:

```bash
uv run codex-inspector observe --watch --interval 2
uv run codex-inspector dashboard
```

The dashboard can run an observe cycle on demand or on each auto-refresh interval. Environment variables:

- `CODEX_INSPECTOR_DB` — database path
- `CODEX_INSPECTOR_CANDIDATE_DIRS` — `os.pathsep`-separated directories to scan during observe/discover
- `CODEX_INSPECTOR_IDLE_SECONDS` — idle threshold for passive `completed`/`stale` transitions (default `30`)

Explicitly attach a process or readable source:

```bash
uv run codex-inspector attach --pid <pid>
uv run codex-inspector attach --path ./codex-session.jsonl
uv run codex-inspector attach --path ./session-directory/
```

Passive runs use observation quality labels:

| Label | Meaning |
|-------|---------|
| `wrapped_full` | Launched through `codex-inspector run` with full JSONL capture |
| `imported_full` | Imported from a saved JSONL/transcript/fixture source |
| `passive_partial` | At least one readable local source was tailed incrementally |
| `process_only` | Only local process metadata is available (no readable event source yet) |
| `unknown` | Legacy or incomplete records |

Run status values include `active`, `stale`, `completed`, `imported`, `failed`, and `unknown`. Passive runs may transition from `active` to `completed` when terminal evidence is seen and sources go idle, or to `stale` when evidence stops without a clean terminal signal.

The dashboard shows passive runs with warnings, last-seen timestamps, confidence, and an Observed Sources tab. Enable **Auto-refresh active sessions** to run an observe cycle before each reload, or use **Run observe cycle now** for a manual refresh.

Run the built-in validation suite:

```bash
uv run codex-inspector self-test
```

Run the unittest suite:

```bash
uv run python -m unittest discover -s tests
```

Update dependencies and refresh the lockfile after editing `pyproject.toml`:

```bash
uv lock
uv sync --all-groups
```

## Data Collected

The inspector stores normalized events, redacted raw payloads, shell commands, command outputs summarized to bounded text, files read or written when observable, git branch/head/status evidence, diff stats, import metadata, passive process/source metadata, cursor positions, observation quality, confidence, and risk findings. Full diffs are captured only with `--include-full-diff`.

## Privacy and Security

Data is stored locally in `.codex-inspector/codex-inspector.sqlite` by default. The dashboard binds to `127.0.0.1` when launched through the CLI. Raw payloads are redacted by default for obvious API keys, bearer tokens, passwords, private keys, `.env`-style values, and token query parameters. Use `--preserve-raw` only for trusted local analysis.

Passive observation uses only local process metadata and explicit or configured readable files/directories. It does not attach debuggers, scrape terminal screens, inspect process memory, collect environment variables by default, send data to external services, or infer hidden model reasoning.

## Limitations

Codex event schemas may change; unknown events are preserved and shown as `unknown`. File attribution is based on observable events and git before/after snapshots, not hidden reasoning. Transcript import and passive source ingestion are intentionally best-effort because Codex local transcript formats can vary. A `process_only` run is useful for live visibility but contains no event stream until a readable source is attached or discovered.

## Troubleshooting

- `Codex CLI was not found on PATH`: install/configure Codex CLI or run `uv run codex-inspector import-fixtures`.
- `Streamlit is not installed`: run `uv sync --group dashboard`.
- No runs in the dashboard: run `uv run codex-inspector import-fixtures` or `uv run codex-inspector run ...`.
- Passive run has no events: it is probably `process_only`; attach a JSONL/transcript/log file with `uv run codex-inspector attach --path ...` or pass `--candidate-dir` to `observe`.

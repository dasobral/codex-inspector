from __future__ import annotations

import argparse
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from .analyzer import build_quality_report
    from .observe_cycle import run_observation_cycle
    from .storage import Storage, default_db_path
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from codex_inspector.analyzer import build_quality_report
    from codex_inspector.observe_cycle import run_observation_cycle
    from codex_inspector.storage import Storage, default_db_path


def launch_dashboard(db_path: str | Path | None = None) -> None:
    import streamlit as st

    storage = Storage(db_path)
    storage.init_schema()
    st.set_page_config(page_title="Codex Run Inspector", layout="wide")
    st.title("Codex Run Inspector")
    st.caption("Local observability for Codex CLI runs. Raw payload display is redacted unless explicitly preserved at import/run time.")
    if st.sidebar.button("Run observe cycle now"):
        run_observation_cycle(storage)
        st.rerun()
    if st.sidebar.checkbox("Auto-refresh active sessions", value=False):
        interval = st.sidebar.number_input("Refresh seconds", min_value=1.0, max_value=60.0, value=2.0, step=1.0)
        st.sidebar.caption("Each refresh runs one passive observe cycle before reloading stored evidence.")
        run_observation_cycle(storage)
        time.sleep(float(interval))
        st.rerun()

    runs = storage.list_runs(limit=200)
    groups = group_runs_by_status(runs)
    if not runs:
        st.info("No runs found. Import synthetic fixtures or run Codex through the wrapper.")
        st.code("codex-inspector import-fixtures\ncodex-inspector dashboard")
        return

    selected_group = st.sidebar.selectbox("Status", options=list(groups.keys()))
    group_runs = groups[selected_group] or runs
    selected_id = st.sidebar.selectbox(
        "Run",
        options=[run["run_id"] for run in group_runs],
        format_func=lambda run_id: _run_label(next(run for run in runs if run["run_id"] == run_id)),
    )
    run = storage.get_run(selected_id) or {}
    events = storage.get_events(selected_id)
    commands = storage.get_commands(selected_id)
    files = storage.get_files(selected_id)
    snapshots = storage.get_git_snapshots(selected_id)
    findings = storage.get_findings(selected_id)
    observed_processes = storage.get_observed_processes(selected_id)
    observed_sources = storage.get_observed_sources(selected_id)

    _overview(st, run, events, commands, files, findings)
    tabs = st.tabs([
        "Timeline",
        "Turns",
        "Commands",
        "File Impact",
        "Sandbox & Approvals",
        "Git Evidence",
        "Quality Report",
        "Observed Sources",
    ])
    with tabs[0]:
        _timeline(st, events)
    with tabs[1]:
        _turns(st, events)
    with tabs[2]:
        _commands(st, commands, findings)
    with tabs[3]:
        _files(st, files)
    with tabs[4]:
        _sandbox_approvals(st, events)
    with tabs[5]:
        _git(st, snapshots)
    with tabs[6]:
        _quality(st, run, events, commands, files, snapshots, findings)
    with tabs[7]:
        _observed_sources(st, observed_processes, observed_sources)


def _overview(st: Any, run: dict[str, Any], events: list[dict[str, Any]], commands: list[dict[str, Any]], files: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    st.subheader("Overview")
    cols = st.columns(6)
    cols[0].metric("Events", len(events))
    cols[1].metric("Commands", len([cmd for cmd in commands if cmd.get("command")]))
    cols[2].metric("Files", len({file["path"] for file in files}))
    cols[3].metric("Failures", len([cmd for cmd in commands if cmd.get("exit_code") not in (None, 0)]))
    cols[4].metric("Risk", run.get("risk_score", 0))
    cols[5].metric("High Findings", len([finding for finding in findings if finding["severity"] in {"high", "critical"}]))
    st.write(
        {
            "status": run.get("status"),
            "observation_quality": run.get("observation_quality"),
            "confidence": run.get("confidence"),
            "last_seen_at": run.get("last_seen_at"),
            "last_event_at": run.get("last_event_at"),
            "repository": run.get("repo_path"),
            "started_at": run.get("started_at"),
            "finished_at": run.get("finished_at"),
            "prompt": run.get("prompt"),
        }
    )
    if run.get("observation_quality") in {"passive_partial", "process_only"}:
        st.warning("This run was observed passively and may be incomplete. The inspector is only showing local evidence it could read.")
    if findings:
        st.write("Findings")
        st.dataframe(
            [
                {
                    "severity": finding["severity"],
                    "category": finding["category"],
                    "reason": finding["reason"],
                    "recommended_action": finding["recommended_action"],
                }
                for finding in findings
            ],
            width="stretch",
        )


def _timeline(st: Any, events: list[dict[str, Any]]) -> None:
    st.subheader("Timeline")
    event_types = sorted({event["normalized_event_type"] for event in events})
    selected_types = st.multiselect("Event types", event_types, default=event_types)
    risk_levels = sorted({event.get("risk_level") for event in events if event.get("risk_level")})
    selected_risks = st.multiselect("Risk levels", risk_levels, default=risk_levels)
    filtered = [
        event
        for event in events
        if event["normalized_event_type"] in selected_types
        and (not risk_levels or not event.get("risk_level") or event.get("risk_level") in selected_risks)
    ]
    st.dataframe([_event_summary(event) for event in filtered], width="stretch")
    for event in filtered:
        label = f"{event['timestamp']} | {event['normalized_event_type']} | {event.get('command') or event.get('tool_name') or event.get('error_message') or ''}"
        with st.expander(label):
            st.json(event.get("raw_payload") or {})


def _turns(st: Any, events: list[dict[str, Any]]) -> None:
    st.subheader("Codex Turn Inspector")
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for event in events:
        groups[event.get("turn_id") or "unassigned"].append(event)
    for turn_id, turn_events in groups.items():
        with st.expander(f"{turn_id} ({len(turn_events)} events)", expanded=turn_id != "unassigned"):
            st.dataframe([_event_summary(event) for event in turn_events], width="stretch")


def _commands(st: Any, commands: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    st.subheader("Command Inspector")
    st.dataframe(commands, width="stretch")
    command_findings = [finding for finding in findings if finding.get("category") in {"failed_command", "destructive_command", "network_command", "privilege_escalation", "dependency_change", "repeated_failure"}]
    if command_findings:
        st.write("Command-related findings")
        st.dataframe(command_findings, width="stretch")


def _files(st: Any, files: list[dict[str, Any]]) -> None:
    st.subheader("File Impact")
    if not files:
        st.info("No file impact was observed.")
        return
    st.dataframe(files, width="stretch")


def _sandbox_approvals(st: Any, events: list[dict[str, Any]]) -> None:
    st.subheader("Sandbox & Approvals")
    relevant = [
        event
        for event in events
        if event["normalized_event_type"] in {"approval_requested", "approval_granted", "approval_denied", "sandbox_event"}
        or event.get("approval_mode")
        or event.get("sandbox_mode")
    ]
    if not relevant:
        st.info("No sandbox or approval events were observed.")
        return
    st.dataframe([_event_summary(event) for event in relevant], width="stretch")


def _git(st: Any, snapshots: list[dict[str, Any]]) -> None:
    st.subheader("Git Evidence")
    if not snapshots:
        st.info("No git snapshots recorded.")
        return
    st.dataframe(
        [
            {
                "phase": snapshot["phase"],
                "repo_path": snapshot["repo_path"],
                "is_git_repo": bool(snapshot["is_git_repo"]),
                "branch": snapshot["branch"],
                "head": snapshot["head"],
                "dirty": snapshot["is_dirty"],
                "changed_files": ", ".join(snapshot.get("changed_files") or []),
            }
            for snapshot in snapshots
        ],
        width="stretch",
    )
    for snapshot in snapshots:
        with st.expander(f"{snapshot['phase']} diff summary"):
            st.code(snapshot.get("diff_summary") or "No diff summary captured.")
            if snapshot.get("full_diff") and st.checkbox(f"Show full diff for {snapshot['phase']}"):
                st.warning("Full diffs may contain secrets. Review before sharing.")
                st.code(snapshot["full_diff"])


def _quality(st: Any, run: dict[str, Any], events: list[dict[str, Any]], commands: list[dict[str, Any]], files: list[dict[str, Any]], snapshots: list[dict[str, Any]], findings: list[dict[str, Any]]) -> None:
    st.subheader("Quality Report")
    report = run.get("summary") or build_quality_report(run, events, commands, files, snapshots, findings)
    st.text(report)


def _observed_sources(st: Any, processes: list[dict[str, Any]], sources: list[dict[str, Any]]) -> None:
    st.subheader("Observed Sources")
    if processes:
        st.write("Processes")
        st.dataframe(processes, width="stretch")
    if sources:
        st.write("Files")
        st.dataframe(sources, width="stretch")
    if not processes and not sources:
        st.info("No passive observation sources are associated with this run.")


def group_runs_by_status(runs: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups = {
        "Active": [],
        "Stale": [],
        "Completed": [],
        "Imported": [],
        "Failed/Unknown": [],
    }
    for run in runs:
        status = run.get("status") or "unknown"
        if status == "active":
            groups["Active"].append(run)
        elif status == "stale":
            groups["Stale"].append(run)
        elif status == "completed":
            groups["Completed"].append(run)
        elif status == "imported":
            groups["Imported"].append(run)
        else:
            groups["Failed/Unknown"].append(run)
    return groups


def _event_summary(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "timestamp": event.get("timestamp"),
        "type": event.get("normalized_event_type"),
        "actor": event.get("actor"),
        "tool": event.get("tool_name"),
        "command": event.get("command"),
        "exit": event.get("command_exit_code"),
        "error": event.get("error_message"),
        "risk": event.get("risk_level"),
    }


def _run_label(run: dict[str, Any]) -> str:
    prompt = (run.get("prompt") or "").replace("\n", " ")
    quality = run.get("observation_quality") or "unknown"
    return f"{run['run_id'][:12]} | {run.get('status') or 'unknown'} | {quality} | risk {run.get('risk_score', 0)} | {prompt[:60]}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=str(default_db_path()))
    args = parser.parse_args()
    launch_dashboard(args.db)


if __name__ == "__main__":
    main()

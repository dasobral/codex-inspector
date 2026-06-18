from __future__ import annotations

import re
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .schemas import Finding
from .storage import Storage, is_sensitive_path

SEVERITY_POINTS = {"info": 1, "warning": 6, "high": 18, "critical": 40}

DESTRUCTIVE_PATTERNS = [
    re.compile(r"\brm\s+-[^&|;]*r[^&|;]*f\b"),
    re.compile(r"\bgit\s+reset\s+--hard\b"),
    re.compile(r"\bgit\s+clean\b"),
    re.compile(r"\bgit\s+push\b.*\s--force(?:-with-lease)?\b"),
]
NETWORK_PATTERN = re.compile(r"\b(curl|wget|nc|netcat|ssh|scp|rsync)\b")
PRIVILEGE_PATTERN = re.compile(r"(^|\s)(sudo|su)\s+")
PACKAGE_PATTERN = re.compile(r"\b(npm|pnpm|yarn|pip|uv|poetry|cargo|go)\b")
TEST_PATTERN = re.compile(r"\b(pytest|unittest|npm\s+test|pnpm\s+test|yarn\s+test|cargo\s+test|go\s+test|mvn\s+test|gradle\s+test)\b")


def analyze_run(storage: Storage, run_id: str) -> dict[str, Any]:
    run = storage.get_run(run_id)
    events = storage.get_events(run_id)
    commands = storage.get_commands(run_id)
    files = storage.get_files(run_id)
    snapshots = storage.get_git_snapshots(run_id)
    findings = build_findings(run or {}, events, commands, files, snapshots)
    storage.replace_findings(run_id, findings)
    event_count = len(events)
    command_count = len([cmd for cmd in commands if cmd.get("command")])
    file_count = len({file["path"] for file in files})
    failure_count = len([cmd for cmd in commands if cmd.get("exit_code") not in (None, 0)])
    high_risk_count = len([finding for finding in findings if finding.severity in {"high", "critical"}])
    risk_score = min(100, sum(SEVERITY_POINTS.get(finding.severity, 0) for finding in findings))
    finding_dicts = [asdict(finding) for finding in findings]
    summary = build_quality_report(run or {}, events, commands, files, snapshots, finding_dicts)
    storage.update_run(
        run_id,
        event_count=event_count,
        command_count=command_count,
        file_count=file_count,
        failure_count=failure_count,
        risk_score=risk_score,
        high_risk_count=high_risk_count,
        summary=summary,
    )
    return {
        "run_id": run_id,
        "event_count": event_count,
        "command_count": command_count,
        "file_count": file_count,
        "failure_count": failure_count,
        "risk_score": risk_score,
        "high_risk_count": high_risk_count,
        "findings": finding_dicts,
        "summary": summary,
    }


def build_findings(
    run: dict[str, Any],
    events: list[dict[str, Any]],
    commands: list[dict[str, Any]],
    files: list[dict[str, Any]],
    snapshots: list[dict[str, Any]],
) -> list[Finding]:
    findings: list[Finding] = []
    run_id = run.get("run_id") or (events[0]["run_id"] if events else "")
    command_failures: dict[str, int] = {}
    for command in commands:
        text = command.get("command") or ""
        event_id = command.get("event_id")
        exit_code = command.get("exit_code")
        if exit_code not in (None, 0):
            command_failures[text] = command_failures.get(text, 0) + 1
            findings.append(
                Finding(
                    run_id,
                    "warning",
                    f"Shell command exited non-zero: {text}",
                    event_id,
                    "Review stderr and verify the failure was resolved.",
                    "failed_command",
                )
            )
        lowered = text.lower()
        if any(pattern.search(lowered) for pattern in DESTRUCTIVE_PATTERNS):
            findings.append(
                Finding(run_id, "critical", f"Destructive command observed: {text}", event_id, "Confirm this command was intended and recoverable.", "destructive_command")
            )
        if PRIVILEGE_PATTERN.search(lowered):
            findings.append(
                Finding(run_id, "high", f"Privilege escalation command observed: {text}", event_id, "Verify why elevated privileges were required.", "privilege_escalation")
            )
        if NETWORK_PATTERN.search(lowered):
            findings.append(
                Finding(run_id, "warning", f"Network-capable command observed: {text}", event_id, "Confirm the network operation is expected.", "network_command")
            )
        if PACKAGE_PATTERN.search(lowered):
            findings.append(
                Finding(run_id, "warning", f"Package manager or dependency command observed: {text}", event_id, "Review dependency and lockfile changes.", "dependency_change")
            )

    for command, count in command_failures.items():
        if command and count > 1:
            findings.append(
                Finding(run_id, "high", f"Repeated command failure ({count} times): {command}", None, "Check for unresolved loops or brittle fixes.", "repeated_failure")
            )

    for event in events:
        if event.get("normalized_event_type") == "diagnostic" and "malformed_jsonl" in event.get("tags", []):
            findings.append(
                Finding(run_id, "warning", "Malformed JSONL line was preserved as a diagnostic event.", event.get("event_id"), "Inspect the raw diagnostic payload for Codex output drift.", "malformed_event_stream")
            )
        if event.get("normalized_event_type") == "approval_denied":
            findings.append(
                Finding(run_id, "high", "Approval request was denied.", event.get("event_id"), "Check whether the denied operation left the task incomplete.", "approval")
            )
        if event.get("normalized_event_type") == "sandbox_event" and _event_mentions_block(event):
            findings.append(
                Finding(run_id, "warning", "Sandbox block or failure was observed.", event.get("event_id"), "Confirm the command was retried safely or the task adapted.", "sandbox")
            )
        if event.get("normalized_event_type") == "run_finished" and event.get("command_exit_code") not in (None, 0):
            findings.append(
                Finding(run_id, "high", "Codex process exited non-zero.", event.get("event_id"), "Review terminal stderr and final state before trusting the run.", "codex_exit")
            )

    for file in files:
        path = file.get("path") or ""
        access = file.get("access_type")
        if access in {"write", "changed_after_run", "git_after"} and is_sensitive_path(path):
            findings.append(
                Finding(run_id, "high", f"Sensitive file touched: {path}", file.get("event_id"), "Review the diff carefully before committing.", "sensitive_file")
            )
        if _is_lockfile(path):
            findings.append(
                Finding(run_id, "warning", f"Dependency lockfile changed or touched: {path}", file.get("event_id"), "Verify dependency updates are intentional.", "lockfile")
            )
        if _is_deployment_file(path):
            findings.append(
                Finding(run_id, "high", f"Deployment or CI/CD file touched: {path}", file.get("event_id"), "Review deployment impact and required approvals.", "deployment")
            )
        if _outside_repo(path, run.get("repo_path")):
            findings.append(
                Finding(run_id, "high", f"Path appears outside repository root: {path}", file.get("event_id"), "Confirm the operation did not modify unrelated files.", "outside_repo")
            )

    wrote_code = any(file.get("access_type") in {"write", "changed_after_run", "git_after"} for file in files)
    ran_tests = any(is_test_command(command.get("command") or "") for command in commands)
    if wrote_code and not ran_tests:
        findings.append(
            Finding(run_id, "warning", "Files changed but no test command was observed.", None, "Run an appropriate test command or document why tests were not applicable.", "missing_tests")
        )

    if run.get("codex_exit_code") not in (None, 0):
        findings.append(
            Finding(run_id, "high", "Recorded Codex exit code is non-zero.", None, "Review the run before relying on its final state.", "codex_exit")
        )

    for snapshot in snapshots:
        diff_summary = snapshot.get("diff_summary") or ""
        if len(diff_summary.splitlines()) > 25:
            findings.append(
                Finding(run_id, "warning", "Large diff summary detected.", None, "Review changed files in smaller groups.", "large_diff")
            )
    return _dedupe_findings(findings)


def build_quality_report(
    run: dict[str, Any],
    events: list[dict[str, Any]],
    commands: list[dict[str, Any]],
    files: list[dict[str, Any]],
    snapshots: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> str:
    ran_tests = any(is_test_command(command.get("command") or "") for command in commands)
    failed_commands = [command for command in commands if command.get("exit_code") not in (None, 0)]
    touched_sensitive = [file.get("path") for file in files if is_sensitive_path(file.get("path") or "")]
    changed_dependencies = [file.get("path") for file in files if _is_lockfile(file.get("path") or "")]
    destructive = [
        command.get("command")
        for command in commands
        if any(pattern.search((command.get("command") or "").lower()) for pattern in DESTRUCTIVE_PATTERNS)
    ]
    high_findings = [finding for finding in findings if finding.get("severity") in {"high", "critical"}]
    observation_quality = run.get("observation_quality") or "unknown"
    confidence = run.get("confidence")
    lines = [
        f"Observation quality: {observation_quality}.",
        f"Observation confidence: {confidence if confidence is not None else 'unknown'}.",
        f"Tests observed: {'yes' if ran_tests else 'no'}.",
        f"Failed commands: {len(failed_commands)}.",
        f"Sensitive files touched: {len(set(touched_sensitive))}.",
        f"Dependency or lockfile changes: {len(set(changed_dependencies))}.",
        f"Destructive commands: {len(destructive)}.",
        f"High or critical findings: {len(high_findings)}.",
    ]
    if observation_quality in {"passive_partial", "process_only"}:
        lines.append("This run was observed passively and may be incomplete; only readable local evidence is shown.")
    if observation_quality == "process_only":
        lines.append("No readable event or transcript source is associated with this run.")
    if snapshots:
        after = snapshots[-1]
        changed = after.get("changed_files") or []
        lines.append(f"Git changed files after run: {len(changed)}.")
    if run.get("codex_exit_code") not in (None, 0):
        lines.append("Final state is not fully credible until the non-zero Codex exit is reviewed.")
    elif high_findings:
        lines.append("Final state needs review because high-risk observable evidence exists.")
    elif failed_commands:
        lines.append("Final state needs review because one or more commands failed.")
    elif ran_tests:
        lines.append("Observable evidence is credible if the displayed test command covers the changed behavior.")
    else:
        lines.append("Observable evidence is incomplete because no test command was recorded.")
    return "\n".join(lines)


def is_test_command(command: str) -> bool:
    return bool(TEST_PATTERN.search(command.lower()))


def _event_mentions_block(event: dict[str, Any]) -> bool:
    text = " ".join(
        str(event.get(key) or "")
        for key in ("error_message", "command_stderr_summary", "approval_status")
    ).lower()
    raw = str(event.get("raw_payload") or "").lower()
    return any(term in f"{text} {raw}" for term in ("blocked", "denied", "sandbox", "permission"))


def _is_lockfile(path: str) -> bool:
    name = Path(path).name.lower()
    return name in {"package-lock.json", "pnpm-lock.yaml", "yarn.lock", "poetry.lock", "cargo.lock", "go.sum"}


def _is_deployment_file(path: str) -> bool:
    lowered = path.lower()
    return any(term in lowered for term in (".github/workflows", ".gitlab-ci", "dockerfile", "deploy", "kubernetes", "helm", "terraform"))


def _outside_repo(path: str, repo_path: str | None) -> bool:
    if not repo_path or not path:
        return False
    candidate = Path(path)
    if not candidate.is_absolute():
        return False
    try:
        candidate.resolve().relative_to(Path(repo_path).resolve())
    except ValueError:
        return True
    return False


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[Finding] = []
    for finding in findings:
        key = (finding.severity, finding.reason, finding.evidence_event_id)
        if key in seen:
            continue
        seen.add(key)
        result.append(finding)
    return result

from __future__ import annotations

import argparse
import importlib.metadata
import inspect
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP

import operator_policy as op_policy
import operator_cron as op_cron
import operator_skills as op_skills
import operator_config as op_config
import operator_workspace as op_workspace
import operator_diagnostics as op_diagnostics
import operator_bridge as op_bridge
import operator_auth as op_auth
import operator_sessions as op_sessions
import operator_policy_templates as op_templates
import operator_delegation as op_delegation
import dcr_compat

try:
    import operator_agent as op_agent
    OPERATOR_AGENT_IMPORT_ERROR: str | None = None
except ModuleNotFoundError as exc:
    if exc.name != "operator_agent":
        raise
    op_agent = None
    OPERATOR_AGENT_IMPORT_ERROR = str(exc)


LOCAL_DEV_PROFILE = "local-dev"
REMOTE_PROFILE = "remote"
CHATGPT_RESTRICTED_PROFILE = "chatgpt-restricted"
CHATGPT_OPERATOR_PROFILE = "chatgpt-operator"
LOCAL_OWNER_PROFILE = "local-owner"
UNSAFE_REMOTE_ACK = "--i-understand-this-is-unsafe"
UNSAFE_REMOTE_ENV = "HERMES_GPT_UNSAFE_REMOTE_NOAUTH"
ENABLE_WRITE_ENV = "HERMES_GPT_ENABLE_WRITE"
ENABLE_MEMORY_WRITE_ENV = "HERMES_GPT_ENABLE_MEMORY_WRITE"
ENABLE_SESSION_SEARCH_ENV = "HERMES_GPT_ENABLE_SESSION_SEARCH"
ENABLE_TERMINAL_ENV = "HERMES_GPT_ENABLE_TERMINAL"
ENABLE_BRIDGE_ENV = "HERMES_GPT_ENABLE_BRIDGE"
RESTRICTED_AGENT_MAX_TIMEOUT_SECONDS = 300
RESTRICTED_AGENT_MAX_TURNS = 30
RESTRICTED_TOOL_NAMES = frozenset(
    {
        "hermes_restricted_status",
        "hermes_restricted_agent_run",
        "hermes_ops_brain_query",
    }
)
NOAUTH_META = {"securitySchemes": [{"type": "noauth"}]}
RUNTIME_TRANSPORT = "unknown"
# Release-safety profile of the most recently built server, and the exact set
# of tool names register_tools() actually registered on it. hermes_operator_status()
# reports REGISTERED_TOOL_NAMES verbatim so its self-report can never drift from
# the real MCP tool surface (the stale-inventory bug this replaces). Both are
# populated by register_tools(); see build_server()/register_tools().
RUNTIME_PROFILE = LOCAL_DEV_PROFILE
REGISTERED_TOOL_NAMES: list[str] = []

HERMES_ROOT: Path | None = None
IMPORT_ERROR: str | None = None
file_tools: Any = None
terminal_tool: Any = None
memory_tool: Any = None
skill_manager_tool: Any = None
SessionDB: Any = None
get_hermes_home: Any = None


def eprint(message: str) -> None:
    print(message, file=sys.stderr)


def env_enabled(name: str) -> bool:
    return os.environ.get(name) == "1"


def is_loopback_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


def _enabled_high_risk_envs_for_restricted() -> list[str]:
    return [
        name
        for name in [
            ENABLE_WRITE_ENV,
            ENABLE_MEMORY_WRITE_ENV,
            ENABLE_SESSION_SEARCH_ENV,
            ENABLE_TERMINAL_ENV,
            ENABLE_BRIDGE_ENV,
        ]
        if env_enabled(name)
    ]


def validate_chatgpt_restricted_runtime(*, host: str, transport: str) -> None:
    """Fail closed before serving a no-auth public connector endpoint."""
    if transport not in {"streamable-http", "sse"}:
        raise RuntimeError("chatgpt-restricted profile requires HTTP or SSE transport.")
    if not is_loopback_host(host):
        raise RuntimeError("chatgpt-restricted profile must bind to loopback only.")
    if op_auth.auth_enabled():
        raise RuntimeError("chatgpt-restricted profile must not enable OAuth.")
    high_risk = _enabled_high_risk_envs_for_restricted()
    if high_risk:
        raise RuntimeError(
            "chatgpt-restricted profile refuses high-risk env flags: "
            + ", ".join(sorted(high_risk))
        )

    policy = op_policy.OperatorPolicy()
    if not policy.enabled:
        raise RuntimeError("chatgpt-restricted profile requires read-only operator policy.")
    if policy.level != "read_only":
        raise RuntimeError("chatgpt-restricted profile requires HERMES_GPT_OPERATOR_LEVEL=read_only.")
    if policy.apply_mode != "dry_run":
        raise RuntimeError("chatgpt-restricted profile requires HERMES_GPT_OPERATOR_APPLY_MODE=dry_run.")
    if policy.owner_mode_ready or os.environ.get(op_policy.OWNER_ACK_ENV):
        raise RuntimeError("chatgpt-restricted profile refuses owner acknowledgement.")
    if not policy.allowed_paths:
        raise RuntimeError("chatgpt-restricted profile requires at least one allowed read path.")


def validate_local_owner_runtime(*, host: str) -> None:
    """Local owner HTTP is allowed only on loopback and never through Cloudflare."""
    if not is_loopback_host(host):
        raise RuntimeError("local-owner profile must bind to loopback only.")


def validate_chatgpt_operator_runtime(*, host: str, transport: str) -> None:
    """Fail closed before serving the authenticated Operator connector.

    Deliberately does not require an active Operator Session: the service
    must start and keep serving OAuth/status/session-request tools even
    with no session, or after the last one expired. Per-call mutation
    gating is enforced by OperatorPolicy at tool-call time (see
    require_mutation), not here.
    """
    if transport not in {"streamable-http", "sse"}:
        raise RuntimeError("chatgpt-operator profile requires HTTP or SSE transport.")
    if not is_loopback_host(host):
        raise RuntimeError("chatgpt-operator profile must bind to loopback behind the tunnel.")
    if not op_auth.auth_enabled():
        raise RuntimeError("chatgpt-operator profile requires OAuth authentication.")
    if os.environ.get(op_policy.OWNER_ACK_ENV):
        raise RuntimeError("chatgpt-operator profile refuses owner mode.")


def restricted_path_denied(path: Path) -> bool:
    name = path.name.lower()
    if name in op_policy.DEFAULT_DENIED_DIR_NAMES:
        return True
    return op_policy.is_denied_path(path)


def is_hermes_root(path: Path) -> bool:
    return path.exists() and ((path / "tools").is_dir() or (path / "hermes_state.py").exists())


def candidate_roots() -> list[Path]:
    candidates: list[Path] = []
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        env_path = Path(env_home).expanduser()
        candidates.extend([env_path, env_path / "hermes-agent"])

    home = Path.home()
    candidates.extend(
        [
            home / "AppData" / "Local" / "hermes" / "hermes-agent",
            home / ".hermes" / "hermes-agent",
        ]
    )

    for package in ("hermes-agent", "hermes_agent"):
        try:
            dist = importlib.metadata.distribution(package)
            base = Path(dist.locate_file("")).resolve()
        except Exception:
            continue
        for parent in [base, *base.parents]:
            if parent.name == "hermes-agent":
                candidates.append(parent)
                break

    unique: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        try:
            resolved = candidate.expanduser().resolve()
        except Exception:
            continue
        key = str(resolved).lower()
        if key not in seen:
            unique.append(resolved)
            seen.add(key)
    return unique


def find_hermes_root() -> Path:
    for candidate in candidate_roots():
        if is_hermes_root(candidate):
            return candidate
    raise RuntimeError("Could not find a Hermes Agent source root with a tools directory.")


def add_path_once(path: Path, *, prepend: bool = True) -> None:
    value = str(path)
    existing = {str(Path(p).resolve()).lower() for p in sys.path if p}
    if str(path.resolve()).lower() not in existing:
        if prepend:
            sys.path.insert(0, value)
        else:
            sys.path.append(value)


def add_hermes_to_syspath(root: Path) -> None:
    add_path_once(root)
    if os.name == "nt":
        site_packages = root / "venv" / "Lib" / "site-packages"
    else:
        candidates = sorted((root / "venv" / "lib").glob("python*/site-packages")) if (root / "venv" / "lib").exists() else []
        site_packages = candidates[0] if candidates else root / "venv" / "lib" / "site-packages"
    if site_packages.exists():
        # Keep Hermes' bundled dependencies available for Hermes internals, but do
        # not let them shadow the MCP SDK used to run this sidecar.
        add_path_once(site_packages, prepend=False)


def import_hermes() -> None:
    global HERMES_ROOT, IMPORT_ERROR, file_tools, terminal_tool, memory_tool
    global skill_manager_tool, SessionDB, get_hermes_home
    try:
        HERMES_ROOT = find_hermes_root()
        add_hermes_to_syspath(HERMES_ROOT)
        from tools import file_tools as ft
        from tools import memory_tool as mt
        from tools import terminal_tool as tt

        file_tools = ft
        terminal_tool = tt
        memory_tool = mt

        try:
            from tools import skill_manager_tool as smt

            skill_manager_tool = smt
        except Exception as exc:
            eprint(f"hermes-gpt: skill manager unavailable: {exc}")

        try:
            from hermes_state import SessionDB as SDB
            from hermes_state import get_hermes_home as ghh

            SessionDB = SDB
            get_hermes_home = ghh
        except Exception as exc:
            eprint(f"hermes-gpt: session search unavailable: {exc}")
    except Exception as exc:
        IMPORT_ERROR = str(exc)
        eprint(f"hermes-gpt: Hermes imports failed: {exc}")


def call_with_supported_kwargs(func: Any, **kwargs: Any) -> Any:
    params = inspect.signature(func).parameters
    supported = {key: value for key, value in kwargs.items() if key in params}
    return func(**supported)


def expand_path(value: str | None) -> str | None:
    if value is None:
        return None
    return str(Path(value).expanduser())


def require_imports() -> None:
    if IMPORT_ERROR:
        raise RuntimeError(f"Hermes imports are unavailable: {IMPORT_ERROR}")
    missing = [
        name
        for name, module in {
            "file_tools": file_tools,
            "terminal_tool": terminal_tool,
            "memory_tool": memory_tool,
        }.items()
        if module is None
    ]
    if missing:
        raise RuntimeError(f"Hermes imports are unavailable: missing {', '.join(missing)}")


def skill_roots() -> list[Path]:
    roots: list[Path] = []
    hermes_home = None
    if callable(get_hermes_home):
        try:
            hermes_home = Path(get_hermes_home())
        except Exception:
            hermes_home = None
    if hermes_home is None:
        env_home = os.environ.get("HERMES_HOME")
        hermes_home = Path(env_home).expanduser() if env_home else Path.home() / ".hermes"

    roots.append(hermes_home / "skills")
    profiles = hermes_home / "profiles"
    if profiles.exists():
        roots.extend(path / "skills" for path in profiles.iterdir() if path.is_dir())
    if HERMES_ROOT:
        roots.append(HERMES_ROOT / "skills")

    unique: list[Path] = []
    seen: set[str] = set()
    for root in roots:
        try:
            resolved = root.expanduser().resolve()
        except Exception:
            continue
        key = str(resolved).lower()
        if resolved.exists() and key not in seen:
            unique.append(resolved)
            seen.add(key)
    return unique


def parse_skill_doc(path: Path) -> dict[str, str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    name = path.parent.name
    description = ""
    body = text
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            body = parts[2]
            for line in parts[1].splitlines():
                if ":" not in line:
                    continue
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip().strip("'\"")
                if key == "name" and value:
                    name = value
                elif key == "description" and value:
                    description = value
    if not description:
        for line in body.splitlines():
            clean = line.strip().lstrip("#").strip()
            if clean:
                description = clean[:180]
                break
    return {"name": name, "description": description, "path": str(path)}


def discover_skills() -> list[dict[str, str]]:
    skills: list[dict[str, str]] = []
    for root in skill_roots():
        for skill_md in root.rglob("SKILL.md"):
            try:
                skills.append(parse_skill_doc(skill_md))
            except Exception as exc:
                eprint(f"hermes-gpt: could not read skill {skill_md}: {exc}")
    return sorted(skills, key=lambda item: (item["name"].lower(), item["path"].lower()))


def clean_error(tool_name: str, exc: Exception) -> RuntimeError:
    eprint(f"hermes-gpt: {tool_name} failed: {exc}")
    return RuntimeError(f"{tool_name} failed: {exc}")


import_hermes()


def tool_meta(extra: dict[str, Any] | None = None) -> dict[str, Any]:
    if op_auth.auth_enabled():
        scope = os.environ.get(op_auth.AUTH_SCOPE_ENV, op_auth.DEFAULT_SCOPE).strip() or op_auth.DEFAULT_SCOPE
        meta: dict[str, Any] = {
            "securitySchemes": [{"type": "oauth2", "scopes": [scope]}]
        }
    else:
        meta = dict(NOAUTH_META)
    if extra:
        meta.update(extra)
    return meta


def hermes_read_file(path: str, offset: int = 1, limit: int = 500) -> str:
    try:
        require_imports()
        return file_tools.read_file_tool(path=expand_path(path), offset=offset, limit=limit)
    except Exception as exc:
        raise clean_error("hermes_read_file", exc) from exc


def hermes_write_file(path: str, content: str) -> str:
    try:
        require_imports()
        return file_tools.write_file_tool(path=expand_path(path), content=content)
    except Exception as exc:
        raise clean_error("hermes_write_file", exc) from exc


def hermes_patch(
    path: str,
    old_string: str,
    new_string: str,
    mode: str = "replace",
    replace_all: bool = False,
) -> str:
    try:
        require_imports()
        return call_with_supported_kwargs(
            file_tools.patch_tool,
            mode=mode,
            path=expand_path(path),
            old_string=old_string,
            new_string=new_string,
            replace_all=replace_all,
        )
    except Exception as exc:
        raise clean_error("hermes_patch", exc) from exc


def hermes_search_files(
    pattern: str,
    target: str = "content",
    path: str = ".",
    file_glob: str | None = None,
    limit: int = 50,
) -> str:
    try:
        require_imports()
        return call_with_supported_kwargs(
            file_tools.search_tool,
            pattern=pattern,
            target=target,
            path=expand_path(path),
            file_glob=file_glob,
            limit=limit,
        )
    except Exception as exc:
        raise clean_error("hermes_search_files", exc) from exc


def hermes_run_command(command: str, timeout: int = 30, workdir: str | None = None) -> str:
    try:
        require_imports()
        if not env_enabled(ENABLE_TERMINAL_ENV):
            raise RuntimeError(f"Terminal execution is disabled. Set {ENABLE_TERMINAL_ENV}=1 to enable it.")
        capped_timeout = max(1, min(int(timeout), 120))
        return call_with_supported_kwargs(
            terminal_tool.terminal_tool,
            command=command,
            timeout=capped_timeout,
            workdir=expand_path(workdir),
        )
    except Exception as exc:
        raise clean_error("hermes_run_command", exc) from exc


def hermes_memory(
    action: str,
    target: str = "memory",
    content: str | None = None,
    old_text: str | None = None,
) -> str:
    try:
        require_imports()
        if action not in {"add", "replace", "remove", "search"}:
            raise RuntimeError("Unsupported memory action. Use add, replace, remove, or search.")
        if action in {"add", "replace", "remove"} and not env_enabled(ENABLE_MEMORY_WRITE_ENV):
            raise RuntimeError(f"Memory write actions are disabled. Set {ENABLE_MEMORY_WRITE_ENV}=1 to enable them.")
        return memory_tool.memory_tool(action=action, target=target, content=content, old_text=old_text)
    except Exception as exc:
        raise clean_error("hermes_memory", exc) from exc


def hermes_skill_list() -> str:
    try:
        require_imports()
        skills = discover_skills()
        if not skills:
            return "No Hermes skills found."
        # Deduplicate by name, keeping the first (user-level skills take priority)
        seen_names: set[str] = set()
        unique_skills: list[dict[str, str]] = []
        for skill in skills:
            if skill["name"].lower() not in seen_names:
                seen_names.add(skill["name"].lower())
                unique_skills.append(skill)
        lines = []
        for skill in unique_skills:
            desc = f" - {skill['description']}" if skill["description"] else ""
            lines.append(f"- {skill['name']}{desc}\n  {skill['path']}")
        return "\n".join(lines)
    except Exception as exc:
        raise clean_error("hermes_skill_list", exc) from exc


def hermes_skill_view(name: str) -> str:
    try:
        require_imports()
        query = name.strip().lower()
        matches = [
            skill for skill in discover_skills()
            if skill["name"].lower() == query or Path(skill["path"]).parent.name.lower() == query
        ]
        if not matches:
            return f"No skill matched {name!r}."
        if len(matches) > 1:
            return "Multiple skills matched:\n" + "\n".join(f"- {m['name']}: {m['path']}" for m in matches)
        skill_path = Path(matches[0]["path"])
        # Size guard: if file > 80KB, return bounded chunk with guidance
        MAX_VIEW_BYTES = 80_000
        file_size = skill_path.stat().st_size
        if file_size > MAX_VIEW_BYTES:
            text = skill_path.read_text(encoding="utf-8", errors="replace")
            return text[:MAX_VIEW_BYTES] + f"\n\n--- TRUNCATED (showing {MAX_VIEW_BYTES} of {file_size} bytes). Use hermes_read_file for specific sections. ---"
        return skill_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        raise clean_error("hermes_skill_view", exc) from exc


def hermes_session_search(query: str, limit: int = 20, offset: int = 0) -> str:
    try:
        require_imports()
        if SessionDB is None:
            return "Hermes session search is unavailable in this install: SessionDB import failed."
        db = SessionDB(read_only=True)
        if not hasattr(db, "search_messages"):
            return "Hermes session search is unavailable in this install: search_messages API is missing."
        rows = db.search_messages(query=query, limit=limit, offset=offset)
        if not rows:
            return "No matching Hermes session messages found."
        rendered = []
        for row in rows:
            session_id = row.get("session_id", "")
            role = row.get("role", "")
            content = (row.get("content") or "").replace("\r", " ").replace("\n", " ")
            rendered.append(f"- {session_id} [{role}] {content[:500]}")
        return "\n".join(rendered)
    except Exception as exc:
        message = f"Hermes session search is unavailable in this install: {exc}"
        eprint(f"hermes-gpt: {message}")
        return message


# ---------------------------------------------------------------------------
# Operator / Owner Mode tools
# ---------------------------------------------------------------------------
#
# These wrap the operator_* modules. They are registered unconditionally
# (so MCP clients can see them and understand why they refuse), but
# mutating tools refuse unless the operator policy is explicitly enabled.
#
# Read-only tools (policy/status/audit_tail, cron list/status, skill diff,
# config get, env status, gateway status, git status/diff) work at any
# enabled level. Mutating tools refuse without sufficient level + apply_mode.


def _hermes_root_for_operator() -> Path | None:
    """Return the Hermes data root for operator operations.

    This intentionally normalizes profile-scoped HERMES_HOME values back to the
    shared Hermes data root so operator/profile tools never treat a profile
    directory or the hermes-agent source checkout as the global root.
    """
    return _default_hermes_root()


def _default_hermes_root() -> Path | None:
    """Return the default Hermes root path (the data root, not the agent source)."""
    env_home = os.environ.get("HERMES_HOME")
    if env_home:
        normalized = op_policy.normalize_hermes_data_root(Path(env_home).expanduser())
        if normalized is not None:
            return normalized
    # The Hermes data root is ~/.hermes (Windows: ~/AppData/Local/hermes).
    # The agent source root lives next to it under hermes-agent/ and is not
    # the same path.
    for cand in [
        Path.home() / "AppData" / "Local" / "hermes",
        Path.home() / ".hermes",
    ]:
        try:
            if cand.is_dir():
                return cand
        except OSError:
            continue
    # Final fallback: ~/.hermes even if it doesn't exist (so tests that
    # monkeypatch this can still pass profile_root into the operator tools).
    return Path.home() / ".hermes"


def _active_profile_name() -> str:
    """Return the active Hermes profile name, or 'default'."""
    try:
        env_home = os.environ.get("HERMES_HOME")
        if env_home:
            p = Path(env_home).expanduser().resolve()
            parts = p.parts
            if "profiles" in parts:
                idx = parts.index("profiles")
                if idx + 1 < len(parts):
                    return parts[idx + 1]
        return "default"
    except Exception:
        return "default"


# --- Policy / status / audit (always registered, read-only) ---------------


def hermes_operator_policy() -> str:
    """Return the current operator policy summary. Read-only. Never secrets."""
    try:
        policy = op_policy.OperatorPolicy()
        summary = policy.to_summary()
        summary["success"] = True
        return json.dumps(summary, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="POLICY_SUMMARY_ERROR",
                suggested_action="Check operator environment variables.",
            ),
            indent=2,
        )


def hermes_operator_status() -> str:
    """Return operator runtime status. Read-only. Never secrets."""
    try:
        policy = op_policy.OperatorPolicy()
        project_path = str(Path(__file__).resolve().parent)
        agent_root = str(HERMES_ROOT) if HERMES_ROOT else None
        default_root = str(_default_hermes_root()) if _default_hermes_root() else None
        active_profile = _active_profile_name()

        # Report the tools ACTUALLY registered on the live server for the
        # active release-safety profile. register_tools() captures the exact
        # set it registered into REGISTERED_TOOL_NAMES, so this self-report can
        # never drift from the real MCP tool surface (unlike the previous
        # hardcoded list, which reflected the default profile and omitted the
        # session tools while wrongly listing owner tools).
        registered = list(REGISTERED_TOOL_NAMES)
        result = {
            "success": True,
            "hermes_gpt_project_path": project_path,
            "hermes_agent_root": agent_root,
            "default_hermes_root": default_root,
            "active_profile": active_profile,
            "mcp_profile": RUNTIME_PROFILE,
            "enabled": policy.enabled,
            "level": policy.level,
            "apply_mode": policy.apply_mode,
            "owner_mode_ready": policy.owner_mode_ready,
            # Session-derived authority state, from the same resolver the
            # mutation guards use -- when level is read_only because a session
            # lapsed, this says so instead of leaving the downgrade silent.
            "session": {
                "status": policy.session_status,
                "session_id": policy.session_id,
                "pointed_session_id": policy.pointed_session_id,
                "approved_at": policy.session_approved_at,
                "expires_at": policy.expires_at,
                "failure_reason": policy.session_failure_reason,
                "writable_roots": [str(p) for p in policy.writable_roots] if policy.session_id else [],
            },
            "registered_operator_tools": registered,
            "registered_tool_count": len(registered),
            "audit_log_path": str(op_policy.audit_log_path()),
        }
        return json.dumps(result, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_STATUS_ERROR",
                suggested_action="Check HERMES_HOME and operator environment variables.",
            ),
            indent=2,
        )


def hermes_operator_audit_tail(limit: int = 20) -> str:
    """Return the last ``limit`` audit records. Read-only."""
    try:
        records = op_policy.audit_tail(limit=limit)
        return json.dumps(
            {"success": True, "count": len(records), "records": records}, indent=2
        )
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="audit",
                code="AUDIT_TAIL_ERROR",
                suggested_action="Check audit log path and permissions.",
            ),
            indent=2,
        )


def hermes_operator_session_status() -> str:
    """Return active Operator Session identity, scope, and expiry. Never returns secrets."""
    try:
        policy = op_policy.OperatorPolicy()
        if not policy.session_id:
            # Distinguish "nothing configured" from "configured but lapsed":
            # an expired/revoked/missing/malformed session must be visible AS
            # SUCH, with its identity and expiry, so a client can tell that a
            # previously-approved session lost authority (and why) instead of
            # seeing an unexplained read_only runtime.
            return json.dumps(
                {
                    "success": False,
                    "session_status": policy.session_status,
                    "pointed_session_id": policy.pointed_session_id,
                    "approved_at": policy.session_approved_at,
                    "expires_at": policy.expires_at,
                    "failure_reason": policy.session_failure_reason,
                    "effective_level": policy.level,
                    "effective_apply_mode": policy.apply_mode,
                    "suggested_action": (
                        "Request a new session via hermes_operator_session_request "
                        "and approve it at the local approval centre, then retry."
                    ),
                },
                indent=2,
            )
        record = op_sessions.load_session(policy.session_id)
        oauth_subject, oauth_client_id = op_policy.current_oauth_identity()
        return json.dumps(
            {
                "success": True,
                "session_id": policy.session_id,
                "snapshot_hash": policy.snapshot_hash,
                "issued_at": record.created_at,
                "expires_at": policy.expires_at,
                "approval_state": record.approval_state,
                "level": policy.level,
                "apply_mode": policy.apply_mode,
                "readable_roots": [str(p) for p in policy.readable_roots],
                "writable_roots": [str(p) for p in policy.writable_roots],
                "verbs": policy.verbs,
                "oauth_subject": oauth_subject,
                "oauth_client_id": oauth_client_id,
                "owner_mode_ready": False,
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_SESSION_STATUS_ERROR",
                suggested_action="Create or activate a non-owner Operator Session.",
            ),
            indent=2,
        )


def hermes_operator_session_request_extension(minutes: int = 30) -> str:
    """Request a session extension. This never grants the extension itself —
    a human operator must separately approve it via the local session CLI
    (operator_sessions.py approve-extension). A session can never approve
    its own extension."""
    try:
        policy = op_policy.OperatorPolicy()
        if not policy.session_id:
            raise PermissionError("No active Operator Session is configured.")
        seconds = max(60, min(int(minutes) * 60, op_sessions.EXTENSION_SECONDS))
        request_id = op_sessions.request_extension(policy.session_id, seconds=seconds)
        op_policy.audit_record(
            tool="hermes_operator_session_request_extension",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            summary=f"requested {seconds}s extension",
            extra={"target_session_id": policy.session_id, "request_id": request_id},
        )
        _notify_pending_request(
            "extension",
            request_id,
            {
                "session_id": policy.session_id,
                "current_expiry": policy.expires_at,
                "requested_seconds": seconds,
            },
        )
        return json.dumps(
            {
                "success": True,
                "request_id": request_id,
                "session_id": policy.session_id,
                "requested_seconds": seconds,
                "status": "pending",
                "note": "Requires separate local operator approval before it takes effect.",
            },
            indent=2,
        )
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_SESSION_EXTENSION_ERROR",
                suggested_action="Check the active Operator Session id.",
            ),
            indent=2,
        )


def _notify_pending_request(request_type: str, request_id: str, details: dict) -> None:
    """Best-effort: tell a human a new approval request is waiting, via
    Telegram if configured. Never raises — a notification failure must never
    block or fail the tool call that created the request. The localhost
    approval page needs no push notification since it polls the same
    pending-request tables directly.

    Forwards to the localhost-only approval centre (127.0.0.1:7690) rather
    than sending Telegram messages directly -- this is the internet-facing
    chatgpt-operator connector, so it must never hold the Telegram bot
    token. Only the loopback-bound approval centre does."""
    try:
        import httpx
        httpx.post(
            "http://127.0.0.1:7690/notify",
            json={"request_type": request_type, "request_id": request_id, "details": details},
            timeout=3.0,
        )
    except Exception:
        pass


def hermes_operator_session_request(
    policy_template: str,
    requested_duration_minutes: int = 60,
    reason: str = "",
) -> str:
    """Request a new Operator Session. This never creates authority by
    itself — it only ever records a pending request carrying the fully
    resolved policy for the named template, for a human to approve via
    Telegram, the localhost approval page, or (break-glass) the CLI. The
    remote caller can only name one of the approved policy templates; it
    can never submit raw roots, verbs, or policy JSON."""
    try:
        if not reason or not reason.strip():
            raise ValueError("reason is required.")
        resolved = op_templates.resolve_template(policy_template)
        requested_seconds = max(60, int(requested_duration_minutes) * 60)
        capped_seconds = min(requested_seconds, resolved["max_duration_seconds"])
        request_id = op_sessions.request_session(
            policy_template=policy_template,
            resolved_policy=resolved["policy"],
            requested_duration_seconds=capped_seconds,
            reason=reason.strip(),
        )
        op_policy.audit_record(
            tool="hermes_operator_session_request",
            level="none",
            apply_mode="request-only",
            dry_run=False,
            success=True,
            summary=f"requested session from template {policy_template!r}",
            extra={
                "request_id": request_id,
                "policy_template": policy_template,
                "requested_duration_seconds": capped_seconds,
            },
        )
        _notify_pending_request(
            "session_creation",
            request_id,
            {
                "policy_template": policy_template,
                "resolved_policy": resolved["policy"],
                "requested_duration_seconds": capped_seconds,
                "reason": reason.strip(),
            },
        )
        return json.dumps(
            {
                "success": True,
                "request_id": request_id,
                "policy_template": policy_template,
                "resolved_policy": resolved["policy"],
                "requested_duration_seconds": capped_seconds,
                "status": "pending",
                "note": "Requires local (Telegram or localhost) approval before any session is created.",
            },
            indent=2,
        )
    except (op_templates.UnknownPolicyTemplateError, op_templates.InactivePolicyTemplateError) as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_SESSION_REQUEST_TEMPLATE_ERROR",
                suggested_action=f"Use one of: {', '.join(op_templates.active_template_names())}.",
            ),
            indent=2,
        )
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_SESSION_REQUEST_ERROR",
                suggested_action="Check policy_template, requested_duration_minutes, and reason.",
            ),
            indent=2,
        )


def hermes_operator_session_revoke(session_id: str = "") -> str:
    """Revoke the active Operator Session or an explicitly supplied session id."""
    try:
        policy = op_policy.OperatorPolicy()
        target = (session_id or policy.session_id or "").strip()
        if not target:
            raise ValueError("session_id is required.")
        changed = op_sessions.revoke_session(target)
        op_policy.audit_record(
            tool="hermes_operator_session_revoke",
            level=policy.level,
            apply_mode=policy.apply_mode,
            dry_run=False,
            success=True,
            changed=changed,
            summary="revoked operator session" if changed else "operator session was already revoked or missing",
            extra={"target_session_id": target},
        )
        return json.dumps({"success": True, "revoked": changed, "session_id": target}, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="OPERATOR_SESSION_REVOKE_ERROR",
                suggested_action="Check the active Operator Session id.",
            ),
            indent=2,
        )


def hermes_operator_doctor(profile: str = "default") -> str:
    """Run a read-only health check across operator surfaces."""
    return op_diagnostics.hermes_operator_doctor(
        profile=profile,
        hermes_root=_default_hermes_root(),
        prefer_systemd=(profile == "default"),
    )


def hermes_operator_snapshot(profile: str = "default") -> str:
    """Return a single current-state summary of the operator."""
    return op_diagnostics.hermes_operator_snapshot(
        profile=profile, hermes_root=_default_hermes_root()
    )


def hermes_release_doctor(workdir: str | None = None, full_tests: bool = False, timeout: int = 180) -> str:
    """Check whether the repo/operator is safe to ship."""
    return op_diagnostics.hermes_release_doctor(
        workdir=workdir, full_tests=full_tests, timeout=timeout
    )


def hermes_operator_recover(profile: str = "default", apply: bool = False) -> str:
    """Conservative recovery sequence. Dry-run by default."""
    return op_diagnostics.hermes_operator_recover(
        profile=profile,
        apply=apply,
        hermes_root=_default_hermes_root(),
        prefer_systemd=(profile == "default"),
    )


# --- Cron wrappers (pass hermes_root through) ----------------------------


def hermes_cron_list(profile: str = "default", include_disabled: bool = False) -> str:
    return op_cron.hermes_cron_list(
        profile=profile, include_disabled=include_disabled,
        hermes_root=_default_hermes_root(),
    )


def hermes_cron_status(profile: str = "default") -> str:
    return op_cron.hermes_cron_status(profile=profile, hermes_root=_default_hermes_root())


def hermes_cron_run(profile: str = "default", job_id: str = "", dry_run: bool = True) -> str:
    return op_cron.hermes_cron_run(
        profile=profile, job_id=job_id, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_cron_pause(profile: str = "default", job_id: str = "", reason: str = "", dry_run: bool = True) -> str:
    return op_cron.hermes_cron_pause(
        profile=profile, job_id=job_id, reason=reason, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_cron_copy(source_profile: str, target_profile: str, job_id: str, dry_run: bool = True) -> str:
    return op_cron.hermes_cron_copy(
        source_profile=source_profile, target_profile=target_profile,
        job_id=job_id, dry_run=dry_run, hermes_root=_default_hermes_root(),
    )


def hermes_cron_move(
    source_profile: str,
    target_profile: str,
    job_id: str,
    pause_source: bool = True,
    test_run_target: bool = False,
    dry_run: bool = True,
) -> str:
    return op_cron.hermes_cron_move(
        source_profile=source_profile, target_profile=target_profile,
        job_id=job_id, pause_source=pause_source,
        test_run_target=test_run_target, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


# --- Skill wrappers ------------------------------------------------------


def hermes_skill_diff(
    profile: str = "default",
    name: str = "",
    proposed_content: str | None = None,
    old_string: str | None = None,
    new_string: str | None = None,
    file_path: str = "SKILL.md",
) -> str:
    return op_skills.hermes_skill_diff(
        profile=profile, name=name, proposed_content=proposed_content,
        old_string=old_string, new_string=new_string, file_path=file_path,
        hermes_root=_default_hermes_root(),
    )


def hermes_skill_create(profile: str = "default", name: str = "", content: str = "", dry_run: bool = True) -> str:
    return op_skills.hermes_skill_create(
        profile=profile, name=name, content=content, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_skill_edit(profile: str = "default", name: str = "", content: str = "", dry_run: bool = True) -> str:
    return op_skills.hermes_skill_edit(
        profile=profile, name=name, content=content, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_skill_patch(
    profile: str = "default",
    name: str = "",
    old_string: str = "",
    new_string: str = "",
    file_path: str = "SKILL.md",
    replace_all: bool = False,
    dry_run: bool = True,
) -> str:
    return op_skills.hermes_skill_patch(
        profile=profile, name=name, old_string=old_string, new_string=new_string,
        file_path=file_path, replace_all=replace_all, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_skill_write_file(
    profile: str = "default",
    name: str = "",
    file_path: str = "",
    file_content: str = "",
    dry_run: bool = True,
) -> str:
    return op_skills.hermes_skill_write_file(
        profile=profile, name=name, file_path=file_path,
        file_content=file_content, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_skill_copy(source_profile: str, target_profile: str, name: str, dry_run: bool = True) -> str:
    return op_skills.hermes_skill_copy(
        source_profile=source_profile, target_profile=target_profile,
        name=name, dry_run=dry_run, hermes_root=_default_hermes_root(),
    )


def hermes_skill_sync_to_default(source_profile: str, name: str, dry_run: bool = True) -> str:
    return op_skills.hermes_skill_sync_to_default(
        source_profile=source_profile, name=name, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_skill_delete(profile: str = "default", name: str = "", dry_run: bool = True) -> str:
    return op_skills.hermes_skill_delete(
        profile=profile, name=name, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


# --- Config / env wrappers -----------------------------------------------


def hermes_config_get(profile: str = "default", key_path: str | None = None) -> str:
    return op_config.hermes_config_get(
        profile=profile, key_path=key_path, hermes_root=_default_hermes_root(),
    )


def hermes_config_set(profile: str = "default", key_path: str = "", value: Any = None, dry_run: bool = True) -> str:
    return op_config.hermes_config_set(
        profile=profile, key_path=key_path, value=value, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_config_patch(profile: str = "default", old_string: str = "", new_string: str = "", dry_run: bool = True) -> str:
    return op_config.hermes_config_patch(
        profile=profile, old_string=old_string, new_string=new_string,
        dry_run=dry_run, hermes_root=_default_hermes_root(),
    )


def hermes_env_status(profile: str = "default", keys: list[str] | None = None) -> str:
    return op_config.hermes_env_status(
        profile=profile, keys=keys, hermes_root=_default_hermes_root(),
    )


def hermes_env_set_nonsecret(profile: str = "default", key: str = "", value: str = "", dry_run: bool = True) -> str:
    return op_config.hermes_env_set_nonsecret(
        profile=profile, key=key, value=value, dry_run=dry_run,
        hermes_root=_default_hermes_root(),
    )


def hermes_env_copy_nonsecret(source_profile: str, target_profile: str, key: str, dry_run: bool = True) -> str:
    return op_config.hermes_env_copy_nonsecret(
        source_profile=source_profile, target_profile=target_profile,
        key=key, dry_run=dry_run, hermes_root=_default_hermes_root(),
    )


# --- Gateway / workspace / git / owner wrappers --------------------------


def hermes_gateway_status(profile: str = "default") -> str:
    return op_workspace.hermes_gateway_status(
        profile=profile,
        hermes_root=_default_hermes_root(),
        prefer_systemd=(profile == "default"),
    )


def hermes_gateway_restart(profile: str = "default", dry_run: bool = True) -> str:
    return op_workspace.hermes_gateway_restart(
        profile=profile, dry_run=dry_run, hermes_root=_default_hermes_root(),
    )


def hermes_operator_service_restart(dry_run: bool = True) -> str:
    """Queue the exact ChatGPT operator unit restart after an approval-gated delay."""
    return op_workspace.hermes_operator_service_restart(dry_run=dry_run)


def hermes_workspace_read(path: str, offset: int = 1, limit: int = 500) -> str:
    return op_workspace.hermes_workspace_read(path=path, offset=offset, limit=limit)


def hermes_workspace_patch(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
    dry_run: bool = True,
) -> str:
    return op_workspace.hermes_workspace_patch(
        path=path, old_string=old_string, new_string=new_string,
        replace_all=replace_all, dry_run=dry_run,
    )


def hermes_workspace_write_file(path: str, content: str, dry_run: bool = True) -> str:
    return op_workspace.hermes_workspace_write_file(
        path=path, content=content, dry_run=dry_run,
    )


def hermes_workspace_run_test(command: str, workdir: str | None = None, timeout: int = 120, dry_run: bool = True) -> str:
    return op_workspace.hermes_workspace_run_test(
        command=command, workdir=workdir, timeout=timeout, dry_run=dry_run,
    )


def hermes_workspace_exec(
    argv: list[str],
    workdir: str,
    timeout: int = 300,
    dry_run: bool = True,
) -> str:
    return op_workspace.hermes_workspace_exec(
        argv=argv,
        workdir=workdir,
        timeout=timeout,
        dry_run=dry_run,
    )


def hermes_git_status(workdir: str) -> str:
    return op_workspace.hermes_git_status(workdir=workdir)


def hermes_git_diff(workdir: str, pathspec: str | None = None, stat: bool = False) -> str:
    return op_workspace.hermes_git_diff(workdir=workdir, pathspec=pathspec, stat=stat)


def hermes_workspace_git_commit(
    workdir: str,
    expected_branch: str,
    expected_baseline: str,
    allowed_files: list[str],
    message: str,
    dry_run: bool = True,
) -> str:
    return op_workspace.hermes_workspace_git_commit(
        workdir=workdir,
        expected_branch=expected_branch,
        expected_baseline=expected_baseline,
        allowed_files=allowed_files,
        message=message,
        dry_run=dry_run,
    )


def hermes_delegate_task(
    prompt: str,
    workdir: str,
    mode: str = "apply",
    profile: str = "default",
    max_turns: int = 30,
    timeout: int = 1800,
    allow_web: bool = False,
) -> str:
    """Queue a durable, workspace-confined Hermes task."""
    return op_delegation.hermes_delegate_task(
        prompt=prompt,
        workdir=workdir,
        mode=mode,
        profile=profile,
        max_turns=max_turns,
        timeout=timeout,
        allow_web=allow_web,
    )


def hermes_delegated_task_status(task_id: str) -> str:
    """Return current state for a delegated Hermes task."""
    return op_delegation.hermes_delegated_task_status(task_id)


def hermes_delegated_task_result(task_id: str) -> str:
    """Return output once a delegated Hermes task reaches a terminal state."""
    return op_delegation.hermes_delegated_task_result(task_id)


def hermes_delegated_task_message(task_id: str, message: str) -> str:
    """Attach durable guidance to a delegated Hermes task."""
    return op_delegation.hermes_delegated_task_message(task_id, message)


def hermes_delegated_task_cancel(task_id: str) -> str:
    """Request cancellation of a queued or running delegated Hermes task."""
    return op_delegation.hermes_delegated_task_cancel(task_id)


def hermes_owner_run_command(command: str, timeout: int = 120, workdir: str | None = None, dry_run: bool = True) -> str:
    return op_workspace.hermes_owner_run_command(
        command=command, timeout=timeout, workdir=workdir, dry_run=dry_run,
    )


def hermes_agent_run(
    prompt: str,
    mode: str = "read_only",
    profile: str = "default",
    workdir: str | None = None,
    max_turns: int = 30,
    timeout: int = 300,
    allow_web: bool = False,
    apply: bool = False,
) -> str:
    if op_agent is None:
        return json.dumps(
            op_policy.make_error_envelope(
                layer="operator",
                code="AGENT_RUN_UNAVAILABLE",
                safe_message="hermes_agent_run is unavailable because operator_agent.py is not installed in this package.",
                suggested_action="Use the narrower operator tools, or install a package that includes operator_agent.py.",
                extra={"module": "operator_agent"},
            ),
            indent=2,
        )
    return op_agent.hermes_agent_run(
        prompt=prompt,
        mode=mode,
        profile=profile,
        workdir=workdir,
        max_turns=max_turns,
        timeout=timeout,
        allow_web=allow_web,
        apply=apply,
        transport=RUNTIME_TRANSPORT,
        hermes_root=_hermes_root_for_operator(),
    )


def hermes_owner_patch(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
    dry_run: bool = True,
) -> str:
    return op_workspace.hermes_owner_patch(
        path=path, old_string=old_string, new_string=new_string,
        replace_all=replace_all, dry_run=dry_run,
    )


def hermes_owner_write_file(path: str, content: str, dry_run: bool = True) -> str:
    return op_workspace.hermes_owner_write_file(path=path, content=content, dry_run=dry_run)


def bridge_status(root: str | None = None) -> str:
    return op_bridge.bridge_status(root=root)


def bridge_read(root: str | None = None, max_chars: int = 200000) -> str:
    return op_bridge.bridge_read(root=root, max_chars=max_chars)


def bridge_submit_command(
    command: str,
    workdir: str,
    command_id: str = "",
    root: str | None = None,
) -> str:
    return op_bridge.bridge_submit_command(
        command=command,
        workdir=workdir,
        command_id=command_id,
        root=root,
    )


def bridge_read_result(command_id: str = "", root: str | None = None) -> str:
    return op_bridge.bridge_read_result(command_id=command_id, root=root)


def bridge_write_adjudication(command_id: str, verdict: str, root: str | None = None) -> str:
    return op_bridge.bridge_write_adjudication(command_id=command_id, verdict=verdict, root=root)


def hermes_ops_brain_query(command: str, keyword: str = "", limit: int = 5) -> str:
    """Run the read-only OpsBrain Markdown query prototype.

    This is a narrow wrapper around ~/.hermes/ops-brain/tools/ops_brain_query.py.
    It does not use a shell, does not create an index, and does not inspect
    runtime/session databases. It only reads OpsBrain Markdown through the
    committed query prototype.
    """
    try:
        policy = op_policy.OperatorPolicy()
        policy.require_level("read_only")
        hermes_root = _hermes_root_for_operator()
        if hermes_root is None:
            return "OpsBrain query unavailable: Hermes root could not be resolved."
        ops_brain = hermes_root / "ops-brain"
        if op_policy.is_denied_path(ops_brain):
            return "OpsBrain query unavailable: OpsBrain path is denied by policy."
        if not op_policy.path_under_allowed(ops_brain, policy.allowed_paths):
            return "OpsBrain query unavailable: OpsBrain path is not in HERMES_GPT_OPERATOR_ALLOWED_PATHS."
        script = ops_brain / "tools" / "ops_brain_query.py"
        if not script.is_file():
            return f"OpsBrain query unavailable: missing {script}."

        cmd = (command or "").strip()
        allowed = {"status", "evidence", "linked", "blockers", "next-actions", "projects", "runbooks"}
        if cmd not in allowed:
            return "Unsupported OpsBrain query command. Allowed: " + ", ".join(sorted(allowed))

        lim = max(1, min(int(limit or 5), 20))
        argv: list[str] = [cmd]
        if cmd in {"status", "evidence", "linked"}:
            key = (keyword or "").strip()
            if not key:
                return f"OpsBrain query command {cmd!r} requires keyword."
            argv.append(key)
            argv.extend(["--limit", str(lim)])
        elif cmd == "next-actions":
            argv.extend(["--limit", str(lim)])

        import contextlib
        import io
        module_dir = str(script.parent)
        old_path = list(sys.path)
        try:
            if module_dir not in sys.path:
                sys.path.insert(0, module_dir)
            query_module = __import__("ops_brain_query")
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                rc = int(query_module.main(argv))
            output = buf.getvalue().strip()
            if rc != 0:
                return f"OpsBrain query failed with exit {rc}.\n{output}"
            return output or "OpsBrain query returned no output."
        finally:
            sys.path[:] = old_path
    except Exception as exc:
        return f"OpsBrain query unavailable: {exc}"


def hermes_restricted_status() -> str:
    """Return the public no-auth endpoint posture without secrets."""
    try:
        policy = op_policy.OperatorPolicy()
        payload = {
            "success": True,
            "profile": CHATGPT_RESTRICTED_PROFILE,
            "authentication": "none",
            "tool_surface": sorted(RESTRICTED_TOOL_NAMES),
            "operator_level": policy.level,
            "apply_mode": policy.apply_mode,
            "owner_mode_ready": False,
            "max_agent_timeout_seconds": RESTRICTED_AGENT_MAX_TIMEOUT_SECONDS,
            "max_agent_turns": RESTRICTED_AGENT_MAX_TURNS,
            "mutation": "disabled",
            "bridge_submission": "disabled",
            "secret_access": "denied",
        }
        return json.dumps(payload, indent=2)
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="RESTRICTED_STATUS_ERROR",
                suggested_action="Check restricted endpoint operator environment.",
            ),
            indent=2,
        )


def hermes_restricted_agent_run(
    prompt: str,
    workdir: str,
    mode: str = "read_only",
    profile: str = "default",
    max_turns: int = 12,
    timeout: int = 120,
) -> str:
    """Run a bounded, read-only Hermes inspection for the no-auth endpoint."""
    try:
        if op_agent is None:
            raise RuntimeError("operator_agent.py is unavailable.")
        normalized_mode = str(mode).strip().lower()
        if normalized_mode not in {"plan", "read_only"}:
            raise PermissionError("Restricted endpoint allows only plan or read_only mode.")
        turns = int(max_turns)
        if not 1 <= turns <= RESTRICTED_AGENT_MAX_TURNS:
            raise ValueError(
                f"max_turns must be between 1 and {RESTRICTED_AGENT_MAX_TURNS}."
            )
        capped_timeout = int(timeout)
        if not 1 <= capped_timeout <= RESTRICTED_AGENT_MAX_TIMEOUT_SECONDS:
            raise ValueError(
                "timeout must be between 1 and "
                f"{RESTRICTED_AGENT_MAX_TIMEOUT_SECONDS} seconds; use the local file bridge for longer jobs."
            )

        policy = op_policy.OperatorPolicy()
        policy.require_level("read_only")
        if policy.level != "read_only" or policy.apply_mode != "dry_run" or policy.owner_mode_ready:
            raise PermissionError("Restricted endpoint is not running under read_only/dry_run policy.")
        canonical_profile = op_policy.validate_profile_name(profile)
        policy.require_profile(canonical_profile, _hermes_root_for_operator())

        candidate = Path(workdir).expanduser()
        if not candidate.is_absolute():
            raise ValueError("workdir must be an absolute path.")
        resolved_workdir = candidate.resolve(strict=True)
        if not resolved_workdir.is_dir():
            raise NotADirectoryError("workdir must be an existing directory.")
        if restricted_path_denied(resolved_workdir):
            raise PermissionError("workdir is denied by restricted endpoint policy.")
        policy.require_workspace_path(str(resolved_workdir))

        return op_agent.hermes_agent_run(
            prompt=prompt,
            mode=normalized_mode,
            profile=canonical_profile,
            workdir=str(resolved_workdir),
            max_turns=turns,
            timeout=capped_timeout,
            allow_web=False,
            apply=False,
            transport=RUNTIME_TRANSPORT,
            hermes_root=_hermes_root_for_operator(),
        )
    except Exception as exc:
        return json.dumps(
            op_policy.error_from_exception(
                exc,
                layer="operator",
                code="RESTRICTED_AGENT_RUN_DENIED",
                suggested_action="Use an allowed read-only workdir, or use the local owner endpoint/file bridge for mutation.",
            ),
            indent=2,
        )



def build_server(
    *,
    host: str = "127.0.0.1",
    port: int = 7677,
    http: bool = False,
    include_local_settings: bool = False,
    transport: str | None = None,
    profile: str = LOCAL_DEV_PROFILE,
) -> FastMCP:
    effective_transport = transport or ("streamable-http" if http else "stdio")
    remote_transport = effective_transport in {"streamable-http", "sse"}
    bridge_requested = env_enabled(ENABLE_BRIDGE_ENV)
    oauth_requested = remote_transport and op_auth.auth_enabled()

    if profile == CHATGPT_RESTRICTED_PROFILE:
        validate_chatgpt_restricted_runtime(host=host, transport=effective_transport)
        bridge_requested = False
        oauth_requested = False
    elif profile == CHATGPT_OPERATOR_PROFILE:
        validate_chatgpt_operator_runtime(host=host, transport=effective_transport)
        bridge_requested = False
        oauth_requested = True
    elif profile == LOCAL_OWNER_PROFILE:
        validate_local_owner_runtime(host=host)

    if (
        remote_transport
        and bridge_requested
        and not oauth_requested
        and profile != LOCAL_OWNER_PROFILE
    ):
        raise RuntimeError(
            f"{ENABLE_BRIDGE_ENV}=1 is refused over HTTP/SSE unless "
            f"{op_auth.AUTH_ENABLED_ENV}=1 and OAuth is configured."
        )

    provider = None
    auth_settings = None
    if oauth_requested:
        auth_config = op_auth.AuthRuntimeConfig.from_env()
        provider = op_auth.PersistentOAuthProvider(auth_config)
        auth_settings = provider.auth_settings()

    server = FastMCP(
        "hermes-gpt",
        host=host,
        port=port,
        streamable_http_path="/mcp",
        sse_path="/sse",
        message_path="/messages/",
        stateless_http=http,
        json_response=http,
        auth_server_provider=provider,
        auth=auth_settings,
    )
    if provider is not None:
        op_auth.register_login_routes(server, provider)
    register_tools(server, include_bridge=bridge_requested, profile=profile)
    return server


def chatgpt_operator_tool_list() -> list[Any]:
    """Canonical, ordered tool set for the ``chatgpt-operator`` profile.

    Single source of truth for that profile: ``register_tools()`` registers
    exactly these, and ``hermes_operator_status()`` reports exactly the names
    captured at registration time (``REGISTERED_TOOL_NAMES``). Keeping the set
    here — rather than in two hand-maintained copies — is what makes the
    self-report unable to silently drift from the real MCP tool surface.

    Deliberately excludes: hermes_owner_run_command, hermes_owner_patch,
    hermes_owner_write_file, bridge_submit_command, hermes_config_set,
    hermes_config_patch, hermes_env_set_nonsecret, hermes_gateway_restart,
    hermes_cron_*, hermes_skill_create/edit/patch/write_file/copy/
    sync_to_default/delete, hermes_agent_run (unrestricted agent delegation),
    and any unrestricted host command tool. The registered workspace executor
    is argv-only and Docker-confined. The one service mutation is an exact,
    delayed restart of this connector's own unit, gated by the maintenance
    template and its immutable services:restart grant. See
    docs/hermes-operator-approval-system.md.
    """
    return [
        hermes_ops_brain_query,
        hermes_operator_policy,
        hermes_operator_status,
        hermes_operator_session_status,
        hermes_operator_session_request,
        hermes_operator_session_request_extension,
        hermes_operator_session_revoke,
        hermes_operator_audit_tail,
        hermes_operator_doctor,
        hermes_operator_snapshot,
        hermes_config_get,
        hermes_env_status,
        hermes_gateway_status,
        hermes_operator_service_restart,
        hermes_search_files,
        hermes_workspace_read,
        hermes_workspace_patch,
        hermes_workspace_write_file,
        hermes_workspace_run_test,
        hermes_workspace_exec,
        hermes_workspace_git_commit,
        hermes_delegate_task,
        hermes_delegated_task_status,
        hermes_delegated_task_result,
        hermes_delegated_task_message,
        hermes_delegated_task_cancel,
        hermes_git_status,
        hermes_git_diff,
    ]


def register_tools(
    server: FastMCP,
    *,
    include_bridge: bool = False,
    profile: str = LOCAL_DEV_PROFILE,
) -> None:
    global RUNTIME_PROFILE
    RUNTIME_PROFILE = profile
    registered: list[str] = []

    def add(tool: Any) -> None:
        server.add_tool(tool, meta=tool_meta())
        registered.append(tool.__name__)

    def finalize() -> None:
        global REGISTERED_TOOL_NAMES
        REGISTERED_TOOL_NAMES = sorted(registered)

    if profile == CHATGPT_RESTRICTED_PROFILE:
        restricted_tools = {
            "hermes_restricted_status": hermes_restricted_status,
            "hermes_restricted_agent_run": hermes_restricted_agent_run,
            "hermes_ops_brain_query": hermes_ops_brain_query,
        }
        if set(restricted_tools) != RESTRICTED_TOOL_NAMES:
            raise RuntimeError("Restricted tool registration drifted.")
        for tool in restricted_tools.values():
            add(tool)
        finalize()
        return

    if profile == CHATGPT_OPERATOR_PROFILE:
        for tool in chatgpt_operator_tool_list():
            add(tool)
        finalize()
        return

    add(hermes_read_file)
    add(hermes_search_files)
    add(hermes_memory)
    add(hermes_skill_list)
    add(hermes_skill_view)

    if env_enabled(ENABLE_WRITE_ENV):
        add(hermes_write_file)
        add(hermes_patch)
    if env_enabled(ENABLE_TERMINAL_ENV):
        add(hermes_run_command)
    if env_enabled(ENABLE_SESSION_SEARCH_ENV):
        add(hermes_session_search)

    # --- Operator / Owner Mode tools -----------------------------------
    #
    # Read-only tools are always registered. Mutating tools are registered
    # unconditionally too (per spec: "register with refusal so the user can
    # see why unavailable") — the wrappers above return a JSON error string
    # when the operator policy is not enabled / level is insufficient /
    # apply_mode is dry_run / owner ack is missing.
    if include_bridge:
        add(bridge_status)
        add(bridge_read)
        add(bridge_submit_command)
        add(bridge_read_result)
        add(bridge_write_adjudication)
    add(hermes_ops_brain_query)
    add(hermes_operator_policy)
    add(hermes_operator_status)
    add(hermes_operator_audit_tail)
    add(hermes_operator_doctor)
    add(hermes_operator_snapshot)
    add(hermes_release_doctor)
    add(hermes_operator_recover)

    # Cron
    add(hermes_cron_list)
    add(hermes_cron_status)
    add(hermes_cron_run)
    add(hermes_cron_pause)
    add(hermes_cron_copy)
    add(hermes_cron_move)

    # Skills
    add(hermes_skill_diff)
    add(hermes_skill_create)
    add(hermes_skill_edit)
    add(hermes_skill_patch)
    add(hermes_skill_write_file)
    add(hermes_skill_copy)
    add(hermes_skill_sync_to_default)
    add(hermes_skill_delete)

    # Config / env
    add(hermes_config_get)
    add(hermes_config_set)
    add(hermes_config_patch)
    add(hermes_env_status)
    add(hermes_env_set_nonsecret)
    add(hermes_env_copy_nonsecret)

    # Gateway / workspace / git / owner
    add(hermes_gateway_status)
    add(hermes_gateway_restart)
    add(hermes_workspace_read)
    add(hermes_workspace_patch)
    add(hermes_workspace_write_file)
    add(hermes_workspace_run_test)
    add(hermes_workspace_exec)
    add(hermes_git_status)
    add(hermes_git_diff)
    add(hermes_agent_run)
    add(hermes_owner_run_command)
    add(hermes_owner_patch)
    add(hermes_owner_write_file)
    finalize()


mcp = build_server()


def main() -> None:
    global RUNTIME_TRANSPORT
    parser = argparse.ArgumentParser(description="Hermes Agent MCP sidecar.")
    parser.add_argument("--http", action="store_true", help="Run streamable HTTP transport instead of stdio.")
    parser.add_argument("--sse", action="store_true", help="Run legacy SSE transport instead of stdio.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7677)
    parser.add_argument("--cert", help="Path to SSL certificate file (enables HTTPS)")
    parser.add_argument("--key", help="Path to SSL key file (enables HTTPS)")
    parser.add_argument(
        "--profile",
        choices=[
            LOCAL_DEV_PROFILE,
            REMOTE_PROFILE,
            CHATGPT_RESTRICTED_PROFILE,
            CHATGPT_OPERATOR_PROFILE,
            LOCAL_OWNER_PROFILE,
        ],
        default=LOCAL_DEV_PROFILE,
        help="Release safety profile.",
    )
    parser.add_argument(
        UNSAFE_REMOTE_ACK,
        action="store_true",
        dest="unsafe_remote_ack",
        help="Allow remote profile without auth. For experiments only; not release-safe.",
    )
    args = parser.parse_args()

    if args.http and args.sse:
        raise SystemExit("Choose only one of --http or --sse.")
    if (
        args.profile == REMOTE_PROFILE
        and not op_auth.auth_enabled()
        and not (args.unsafe_remote_ack and env_enabled(UNSAFE_REMOTE_ENV))
    ):
        raise SystemExit(
            f"Remote profile requires {op_auth.AUTH_ENABLED_ENV}=1 with OAuth configured. "
            f"For temporary experiments only, pass {UNSAFE_REMOTE_ACK} and set {UNSAFE_REMOTE_ENV}=1."
        )
    if args.profile == LOCAL_DEV_PROFILE and not is_loopback_host(args.host):
        eprint(
            "WARNING: local-dev profile is bound to a non-loopback host. "
            "Do not expose hermes-gpt without real authentication."
        )
    if args.profile == REMOTE_PROFILE and not op_auth.auth_enabled():
        eprint("WARNING: remote no-auth mode is explicitly unsafe and intended only for temporary experiments.")

    transport = "streamable-http" if args.http else "sse" if args.sse else "stdio"
    if args.profile == CHATGPT_RESTRICTED_PROFILE:
        try:
            validate_chatgpt_restricted_runtime(host=args.host, transport=transport)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
    if args.profile == LOCAL_OWNER_PROFILE:
        try:
            validate_local_owner_runtime(host=args.host)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc
    if args.profile == CHATGPT_OPERATOR_PROFILE:
        try:
            validate_chatgpt_operator_runtime(host=args.host, transport=transport)
        except RuntimeError as exc:
            raise SystemExit(str(exc)) from exc

    RUNTIME_TRANSPORT = transport
    server = build_server(
        host=args.host,
        port=args.port,
        http=args.http,
        transport=transport,
        profile=args.profile,
    )
    if transport == "stdio":
        eprint("hermes-gpt MCP server starting in stdio mode.")
        server.run(transport="stdio")
    else:
        path = "/mcp" if args.http else "/sse"
        eprint(f"hermes-gpt MCP server running at http://{args.host}:{args.port}{path}")

        # Run with uvicorn instead of FastMCP.run() so TLS can be enabled for
        # local-only testing when cert/key are provided.
        import uvicorn
        app = server.streamable_http_app() if args.http else server.sse_app()
        # Register public PKCE clients (e.g. ChatGPT) that request a confidential
        # token_endpoint_auth_method but present no secret. See dcr_compat.
        app = dcr_compat.normalize_public_client_registration(app)

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            ssl_certfile=args.cert if args.cert else None,
            ssl_keyfile=args.key if args.key else None,
            proxy_headers=True,
            forwarded_allow_ips="*",
        )


if __name__ == "__main__":
    main()

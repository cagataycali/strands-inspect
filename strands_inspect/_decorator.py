"""
🔍 @watch decorator — sandbox + record + replay for any Python function.

Wraps a function to:
1. Hook all syscalls (file I/O, network, subprocess, imports) with allow/deny policies
2. Profile memory + CPU during execution
3. Capture all inputs, outputs, side effects, exceptions
4. Dump everything to a .dill file for full session replay
5. Replay: re-execute with same inputs or modify and re-run

Usage:
    from strands_inspect import watch

    @watch
    def my_function(x, y):
        data = open("file.txt").read()
        return process(data, x, y)

    # Runs with full recording + syscall interception
    result = my_function(1, 2)

    # With policy (sandbox mode):
    @watch(policy="deny_network")
    def safe_func():
        import requests  # ← blocked!
        requests.get("http://evil.com")

    # Block EVERYTHING:
    @watch(policy="deny_all")
    def locked_down():
        open("x")       # ← blocked
        os.system("ls")  # ← blocked
        ...

    # Granular path-based policies:
    @watch(policy={
        "file.read": {"action": "allow", "paths": ["/tmp/**", "./data/**"]},
        "file.write": "deny",
        "file.delete": "deny",
        "file.move": "deny",
        "network": {"action": "allow", "hosts": ["api.openai.com", "*.amazonaws.com"]},
        "subprocess": "deny",
        "os.system": "deny",
        "import": {"action": "allow", "packages": ["json", "math", "re"]},
    })
    def sandboxed():
        ...

    # Callable policy (full control):
    @watch(policy={
        "network": lambda action, detail: "allow" if "openai" in detail else "deny",
        "file.read": lambda action, detail: "allow" if "/tmp" in detail else "deny",
    })
    def custom_policy():
        ...

    # Replay a session:
    from strands_inspect import replay
    session = replay("my_function_20260302_035500.dill")
    session.re_run()  # re-execute with same args
    session.re_run(x=10, y=20)  # re-execute with new args
"""

import builtins
import fnmatch
import functools
import hashlib
import importlib as _importlib_mod
import io
import os
import shutil as _shutil_mod
import subprocess as _subprocess_mod
import sys
import time
import traceback
import tracemalloc
import asyncio
import threading
import types
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
from strands_inspect._config import get_named_policy
from urllib.parse import urlparse

# Use dill for better serialization, fall back to pickle
try:
    import dill

    _SERIALIZER = dill
    _SERIALIZER_NAME = "dill"
except ImportError:
    import pickle as dill  # fallback

    _SERIALIZER = dill
    _SERIALIZER_NAME = "pickle"


# ─── Default Dump Directory ─────────────────────────────────────────

DUMP_DIR = Path(
    os.getenv("STRANDS_INSPECT_DUMP_DIR", os.path.join(os.path.expanduser("~"), ".strands_inspect"))
)
DUMP_DIR.mkdir(parents=True, exist_ok=True)


# ─── Policies ───────────────────────────────────────────────────────

# All hookable action categories:
#   file.read     - reading files (builtins.open read mode, os.open O_RDONLY)
#   file.write    - writing files (builtins.open write mode, os.open O_WRONLY/O_RDWR)
#   file.delete   - deleting files/dirs (os.remove, os.unlink, os.rmdir, shutil.rmtree)
#   file.move     - renaming/moving files (os.rename, os.replace)
#   file.chmod    - permission changes (os.chmod, os.chown)
#   network       - any network I/O (socket.connect, urllib, requests, http.client)
#   subprocess    - subprocess module (run, Popen, call, check_output)
#   os.system     - os.system(), os.popen() — shell execution outside subprocess
#   os.exec       - os.exec*(), os.spawn*() — process replacement
#   import        - import statements (__import__, importlib.import_module)
#
# Decision values:
#   "allow"   - allow silently
#   "deny"    - raise PolicyViolation
#   "log"     - allow + record in trace
#   "ask"     - interactive prompt
#   callable  - fn(action, detail) → "allow"|"deny"|"log"
#   dict      - {"action": "allow|deny|log", "paths": [...], "hosts": [...], "packages": [...]}

ALL_CATEGORIES = [
    "file.read",
    "file.write",
    "file.delete",
    "file.move",
    "file.chmod",
    "file.link",
    "file.mkdir",
    "file.fd_io",
    "file.special",
    "network",
    "net.socket",
    "subprocess",
    "os.system",
    "os.exec",
    "process.fork",
    "process.kill",
    "process.mp",
    "import",
    "meta.ctypes",
    "meta.code",
]

BUILTIN_POLICIES = {
    "allow_all": {cat: "log" for cat in ALL_CATEGORIES},
    "deny_all": {cat: "deny" for cat in ALL_CATEGORIES},
    "deny_network": {
        **{cat: "log" for cat in ALL_CATEGORIES},
        "network": "deny",
    },
    "deny_write": {
        **{cat: "log" for cat in ALL_CATEGORIES},
        "file.write": "deny",
        "file.delete": "deny",
        "file.move": "deny",
        "file.chmod": "deny",
    },
    "sandbox": {
        "file.read": "log",
        "file.write": "deny",
        "file.delete": "deny",
        "file.move": "deny",
        "file.chmod": "deny",
        "file.link": "deny",
        "file.mkdir": "deny",
        "file.fd_io": "deny",
        "file.special": "deny",
        "network": "deny",
        "net.socket": "deny",
        "subprocess": "deny",
        "os.system": "deny",
        "os.exec": "deny",
        "process.fork": "deny",
        "process.kill": "deny",
        "process.mp": "deny",
        "import": "log",
        "meta.ctypes": "deny",
        "meta.code": "deny",
    },
    "strict": {
        "file.read": "ask",
        "file.write": "deny",
        "file.delete": "deny",
        "file.move": "deny",
        "file.chmod": "deny",
        "file.link": "deny",
        "file.mkdir": "deny",
        "file.fd_io": "deny",
        "file.special": "deny",
        "network": "deny",
        "net.socket": "deny",
        "subprocess": "deny",
        "os.system": "deny",
        "os.exec": "deny",
        "process.fork": "deny",
        "process.kill": "deny",
        "process.mp": "deny",
        "import": "ask",
        "meta.ctypes": "deny",
        "meta.code": "deny",
    },
}


class PolicyViolation(PermissionError):
    """Raised when a syscall is denied by policy."""

    def __init__(self, action: str, detail: str):
        self.action = action
        self.detail = detail
        super().__init__(f"🚫 Policy denied: {action} — {detail}")


# ─── Granular Policy Matching ────────────────────────────────────────


def _match_path(path_str: str, patterns: List[str]) -> bool:
    """Match a file path against glob patterns."""
    path_str = os.path.abspath(path_str)
    for pattern in patterns:
        pattern = os.path.abspath(pattern) if not pattern.startswith("*") else pattern
        if fnmatch.fnmatch(path_str, pattern):
            return True
        # Also try relative matching
        if fnmatch.fnmatch(os.path.basename(path_str), pattern):
            return True
    return False


def _match_host(detail: str, hosts: List[str]) -> bool:
    """Match a network detail string against host patterns."""
    detail_lower = detail.lower()
    for host_pattern in hosts:
        host_pattern = host_pattern.lower()
        if host_pattern.startswith("*."):
            # Wildcard domain: *.amazonaws.com matches anything.amazonaws.com
            suffix = host_pattern[1:]  # .amazonaws.com
            if suffix in detail_lower:
                return True
        else:
            if host_pattern in detail_lower:
                return True
    return False


def _match_package(name: str, packages: List[str]) -> bool:
    """Match an import name against allowed package patterns."""
    for pkg in packages:
        if name == pkg or name.startswith(pkg + "."):
            return True
        if fnmatch.fnmatch(name, pkg):
            return True
    return False


def _resolve_decision(policy_entry, action: str, detail: str) -> str:
    """Resolve a policy entry to a decision string.

    Supports:
      - str: "allow", "deny", "log", "ask"
      - callable: fn(action, detail) → str
      - dict: {"action": "allow", "paths": [...], "hosts": [...], "packages": [...]}
    """
    if policy_entry is None:
        return "log"

    # Callable policy — full custom control
    if callable(policy_entry):
        try:
            result = policy_entry(action, detail)
            return result if result in ("allow", "deny", "log", "ask") else "deny"
        except Exception:
            return "deny"  # fail closed

    # Dict policy — granular matching
    if isinstance(policy_entry, dict):
        base_action = policy_entry.get("action", "deny")

        # Path-based matching for file actions
        paths = policy_entry.get("paths")
        if paths is not None:
            # Extract the actual path from the detail string
            # Detail format: "/path/to/file (mode=r)" or "/path/to/file"
            path_str = detail.split(" (")[0].strip()
            if _match_path(path_str, paths):
                return base_action
            else:
                return "deny"

        # Host-based matching for network actions
        hosts = policy_entry.get("hosts")
        if hosts is not None:
            if _match_host(detail, hosts):
                return base_action
            else:
                return "deny"

        # Package-based matching for imports
        packages = policy_entry.get("packages")
        if packages is not None:
            if _match_package(detail, packages):
                return base_action
            else:
                return "deny"

        # No filter specified, use base action
        return base_action

    # String policy
    if isinstance(policy_entry, str):
        return policy_entry if policy_entry in ("allow", "deny", "log", "ask") else "log"

    return "log"


# ─── Syscall Event ──────────────────────────────────────────────────


class SyscallEvent:
    """A recorded syscall interception."""

    __slots__ = ("timestamp", "action", "detail", "decision", "duration_ns", "result_preview")

    def __init__(self, action: str, detail: str, decision: str = "allow"):
        self.timestamp = time.time_ns()
        self.action = action
        self.detail = detail
        self.decision = decision
        self.duration_ns = 0
        self.result_preview = None

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "action": self.action,
            "detail": self.detail,
            "decision": self.decision,
            "duration_ns": self.duration_ns,
            "result_preview": self.result_preview,
        }


# ─── Session Dump (the dill file) ───────────────────────────────────


class InspectSession:
    """Complete recorded session from an @inspect'd function call."""

    def __init__(self, func_name: str, func_module: str):
        self.func_name = func_name
        self.func_module = func_module
        self.session_id = f"{func_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.timestamp = datetime.now().isoformat()

        # Inputs
        self.args: tuple = ()
        self.kwargs: dict = {}
        self.source_code: str = ""

        # Outputs
        self.return_value: Any = None
        self.exception: Optional[str] = None
        self.stdout: str = ""
        self.stderr: str = ""

        # Syscall trace
        self.syscalls: List[dict] = []
        self.policy: dict = {}

        # Syscall stats
        self.files_read: List[str] = []
        self.files_written: List[str] = []
        self.files_deleted: List[str] = []
        self.files_moved: List[str] = []
        self.files_chmod: List[str] = []
        self.network_calls: List[str] = []
        self.subprocesses: List[str] = []
        self.os_system_calls: List[str] = []
        self.os_exec_calls: List[str] = []
        self.imports: List[str] = []
        self.denied: List[dict] = []

        # Profiling
        self.wall_time_ms: float = 0
        self.memory_peak_kb: float = 0
        self.memory_timeline: List[dict] = []
        self.memory_allocations: List[dict] = []

        # Function reference for replay
        self._func: Optional[Callable] = None

    def summary(self) -> str:
        """Human-readable session summary."""
        lines = [
            f"🔍 InspectSession: {self.session_id}",
            f"   Function: {self.func_module}.{self.func_name}",
            f"   Time: {self.timestamp}",
            f"   Wall: {self.wall_time_ms:.1f}ms | Peak mem: {self.memory_peak_kb:.1f} KB",
            f"   Args: {len(self.args)} positional, {len(self.kwargs)} keyword",
            f"   Return: {repr(self.return_value)[:100]}",
        ]
        if self.exception:
            lines.append(f"   ❌ Exception: {self.exception[:100]}")
        if self.syscalls:
            lines.append(f"   📋 Syscalls: {len(self.syscalls)} total")
            lines.append(
                f"      Files read: {len(self.files_read)} | written: {len(self.files_written)} | deleted: {len(self.files_deleted)}"
            )
            lines.append(
                f"      Network: {len(self.network_calls)} | Subprocess: {len(self.subprocesses)} | os.system: {len(self.os_system_calls)}"
            )
            lines.append(f"      Imports: {len(self.imports)}")
        if self.denied:
            lines.append(f"   🚫 Denied: {len(self.denied)} syscalls blocked")
            for d in self.denied[:5]:
                lines.append(f"      - {d['action']}: {d['detail'][:80]}")
            if len(self.denied) > 5:
                lines.append(f"      ... and {len(self.denied) - 5} more")
        return "\n".join(lines)

    def re_run(self, *args, **kwargs):
        """Re-execute the function with original or new arguments."""
        if self._func is None:
            raise RuntimeError(
                "Function not available for replay. "
                "Load the module or pass the function manually."
            )
        use_args = args if args else self.args
        use_kwargs = kwargs if kwargs else self.kwargs
        return self._func(*use_args, **use_kwargs)

    def diff(self, other: "InspectSession") -> dict:
        """Compare two sessions."""
        return {
            "wall_time_delta_ms": other.wall_time_ms - self.wall_time_ms,
            "memory_delta_kb": other.memory_peak_kb - self.memory_peak_kb,
            "syscalls_delta": len(other.syscalls) - len(self.syscalls),
            "return_changed": self.return_value != other.return_value,
            "exception_changed": self.exception != other.exception,
            "files_read_diff": set(other.files_read) - set(self.files_read),
            "files_written_diff": set(other.files_written) - set(self.files_written),
            "denied_delta": len(other.denied) - len(self.denied),
        }

    def to_json(self, path: str = None) -> dict:
        """Export session as JSON for the web viewer.

        Produces a unified format that includes both profile data
        and session/syscall data for the interactive timeline.
        """
        import json as _json

        data = {
            "wall_time_ms": self.wall_time_ms,
            "memory": {
                "peak_kb": self.memory_peak_kb,
                "current_kb": 0,
                "top_allocations": self.memory_allocations,
            },
            "timeline": self.memory_timeline,
            "cpu": {"total_calls": 0, "top_functions": []},
            "gc": {},
            "resource": {},
            "stdout": self.stdout,
            "stderr": self.stderr,
            "return_value": (
                repr(self.return_value)[:1000] if self.return_value is not None else None
            ),
            "exception": self.exception,
            "session": {
                "session_id": self.session_id,
                "func_name": self.func_name,
                "func_module": self.func_module,
                "timestamp": self.timestamp,
                "policy": self.policy,
                "source_code": self.source_code,
                "syscalls": self.syscalls,
                "denied": self.denied,
                "stats": {
                    "files_read": len(self.files_read),
                    "files_written": len(self.files_written),
                    "files_deleted": len(self.files_deleted),
                    "files_moved": len(self.files_moved),
                    "files_chmod": len(self.files_chmod),
                    "network_calls": len(self.network_calls),
                    "subprocesses": len(self.subprocesses),
                    "os_system_calls": len(self.os_system_calls),
                    "imports": len(self.imports),
                    "total_denied": len(self.denied),
                },
                "details": {
                    "files_read": self.files_read[:50],
                    "files_written": self.files_written[:50],
                    "files_deleted": self.files_deleted[:50],
                    "network_calls": self.network_calls[:50],
                    "subprocesses": self.subprocesses[:50],
                    "imports": self.imports[:50],
                },
            },
        }

        if path:
            with open(path, "w") as f:
                _json.dump(data, f, indent=2, default=str)

        return data

    def __repr__(self):
        status = "❌" if self.exception else "✅"
        denied_tag = f" 🚫{len(self.denied)}" if self.denied else ""
        return (
            f"InspectSession({status} {self.func_name}, "
            f"{self.wall_time_ms:.1f}ms, "
            f"{self.memory_peak_kb:.0f}KB, "
            f"{len(self.syscalls)} syscalls{denied_tag})"
        )


# ─── Syscall Hooks Engine ───────────────────────────────────────────


class SyscallHooks:
    """Intercepts file I/O, network, subprocess, os.system, imports, and more."""

    def __init__(self, policy: dict):
        self.policy = policy
        self.events: List[SyscallEvent] = []
        self._originals: dict = {}
        self._installed = False

    def _check_policy(self, action: str, detail: str) -> str:
        """Check policy and return decision: allow, deny, log, ask.

        Resolution order:
        1. Exact action match (e.g., "file.read")
        2. Category match (e.g., "file")
        3. Default: "log"
        """
        # Exact match first
        category = action.split(".")[0]
        policy_entry = self.policy.get(action, self.policy.get(category))

        decision = _resolve_decision(policy_entry, action, detail)

        if decision == "deny":
            event = SyscallEvent(action, detail, "deny")
            self.events.append(event)
            raise PolicyViolation(action, detail)

        if decision == "ask":
            answer = (
                input(f"🔍 Allow {action}: {detail}? [y/N] ").strip().lower()
            )  # pragma: no cover
            if answer != "y":
                event = SyscallEvent(action, detail, "deny")
                self.events.append(event)
                raise PolicyViolation(action, detail)
            decision = "allow"

        # Log/allow it
        event = SyscallEvent(action, detail, decision)
        self.events.append(event)
        return decision

    def install(self):
        """Install all syscall hooks."""
        if self._installed:
            return

        hooks = self

        # ── Hook: builtins.open ──────────────────────────────────
        self._originals["open"] = builtins.open

        def hooked_open(file, mode="r", *args, **kwargs):
            path_str = str(file)
            is_write = any(c in mode for c in "wxa+")
            action = "file.write" if is_write else "file.read"
            hooks._check_policy(action, f"{path_str} (mode={mode})")
            t0 = time.time_ns()
            result = hooks._originals["open"](file, mode, *args, **kwargs)
            if hooks.events:
                hooks.events[-1].duration_ns = time.time_ns() - t0
            return result

        builtins.open = hooked_open

        # ── Hook: os.open (low-level fd) ─────────────────────────
        self._originals["os_open"] = os.open

        def hooked_os_open(path, flags, mode=0o777, *args, **kwargs):
            path_str = str(path)
            is_write = bool(
                flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            )
            action = "file.write" if is_write else "file.read"
            hooks._check_policy(action, f"{path_str} (os.open flags={flags:#x})")
            return hooks._originals["os_open"](path, flags, mode, *args, **kwargs)

        os.open = hooked_os_open

        # ── Hook: os.remove / os.unlink ──────────────────────────
        self._originals["os_remove"] = os.remove
        self._originals["os_unlink"] = os.unlink

        def hooked_os_remove(path, *args, **kwargs):
            hooks._check_policy("file.delete", str(path))
            return hooks._originals["os_remove"](path, *args, **kwargs)

        def hooked_os_unlink(path, *args, **kwargs):
            hooks._check_policy("file.delete", str(path))
            return hooks._originals["os_unlink"](path, *args, **kwargs)

        os.remove = hooked_os_remove
        os.unlink = hooked_os_unlink

        # ── Hook: os.rmdir / os.removedirs ───────────────────────
        self._originals["os_rmdir"] = os.rmdir

        def hooked_os_rmdir(path, *args, **kwargs):
            hooks._check_policy("file.delete", str(path))
            return hooks._originals["os_rmdir"](path, *args, **kwargs)

        os.rmdir = hooked_os_rmdir

        if hasattr(os, "removedirs"):
            self._originals["os_removedirs"] = os.removedirs

            def hooked_os_removedirs(path, *args, **kwargs):
                hooks._check_policy("file.delete", str(path))
                return hooks._originals["os_removedirs"](path, *args, **kwargs)

            os.removedirs = hooked_os_removedirs

        # ── Hook: shutil.rmtree ──────────────────────────────────
        self._originals["shutil_rmtree"] = _shutil_mod.rmtree

        def hooked_shutil_rmtree(path, *args, **kwargs):
            hooks._check_policy("file.delete", f"rmtree {path}")
            return hooks._originals["shutil_rmtree"](path, *args, **kwargs)

        _shutil_mod.rmtree = hooked_shutil_rmtree

        # ── Hook: os.rename / os.replace / os.renames ────────────
        self._originals["os_rename"] = os.rename
        self._originals["os_replace"] = os.replace

        def hooked_os_rename(src, dst, *args, **kwargs):
            hooks._check_policy("file.move", f"{src} → {dst}")
            return hooks._originals["os_rename"](src, dst, *args, **kwargs)

        def hooked_os_replace(src, dst, *args, **kwargs):
            hooks._check_policy("file.move", f"{src} → {dst}")
            return hooks._originals["os_replace"](src, dst, *args, **kwargs)

        os.rename = hooked_os_rename
        os.replace = hooked_os_replace

        if hasattr(os, "renames"):
            self._originals["os_renames"] = os.renames

            def hooked_os_renames(old, new, *args, **kwargs):
                hooks._check_policy("file.move", f"{old} → {new}")
                return hooks._originals["os_renames"](old, new, *args, **kwargs)

            os.renames = hooked_os_renames

        # ── Hook: shutil.move / shutil.copy / shutil.copy2 ───────
        self._originals["shutil_move"] = _shutil_mod.move
        self._originals["shutil_copy"] = _shutil_mod.copy
        self._originals["shutil_copy2"] = _shutil_mod.copy2
        self._originals["shutil_copytree"] = _shutil_mod.copytree

        def hooked_shutil_move(src, dst, *args, **kwargs):
            hooks._check_policy("file.move", f"shutil.move {src} → {dst}")
            return hooks._originals["shutil_move"](src, dst, *args, **kwargs)

        def hooked_shutil_copy(src, dst, *args, **kwargs):
            hooks._check_policy("file.write", f"shutil.copy {src} → {dst}")
            return hooks._originals["shutil_copy"](src, dst, *args, **kwargs)

        def hooked_shutil_copy2(src, dst, *args, **kwargs):
            hooks._check_policy("file.write", f"shutil.copy2 {src} → {dst}")
            return hooks._originals["shutil_copy2"](src, dst, *args, **kwargs)

        def hooked_shutil_copytree(src, dst, *args, **kwargs):
            hooks._check_policy("file.write", f"shutil.copytree {src} → {dst}")
            return hooks._originals["shutil_copytree"](src, dst, *args, **kwargs)

        _shutil_mod.move = hooked_shutil_move
        _shutil_mod.copy = hooked_shutil_copy
        _shutil_mod.copy2 = hooked_shutil_copy2
        _shutil_mod.copytree = hooked_shutil_copytree

        # ── Hook: os.chmod / os.chown ────────────────────────────
        self._originals["os_chmod"] = os.chmod

        def hooked_os_chmod(path, mode, *args, **kwargs):
            hooks._check_policy("file.chmod", f"chmod {oct(mode)} {path}")
            return hooks._originals["os_chmod"](path, mode, *args, **kwargs)

        os.chmod = hooked_os_chmod

        if hasattr(os, "chown"):
            self._originals["os_chown"] = os.chown

            def hooked_os_chown(path, uid, gid, *args, **kwargs):
                hooks._check_policy("file.chmod", f"chown {uid}:{gid} {path}")
                return hooks._originals["os_chown"](path, uid, gid, *args, **kwargs)

            os.chown = hooked_os_chown

        # ── Hook: subprocess ─────────────────────────────────────
        self._originals["subprocess_run"] = _subprocess_mod.run
        self._originals["subprocess_Popen"] = _subprocess_mod.Popen
        self._originals["subprocess_call"] = _subprocess_mod.call
        self._originals["subprocess_check_output"] = _subprocess_mod.check_output
        self._originals["subprocess_check_call"] = _subprocess_mod.check_call

        def _cmd_str(args, kwargs):
            cmd = args[0] if args else kwargs.get("args", "?")
            return " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)

        def hooked_run(*args, **kwargs):
            hooks._check_policy("subprocess", _cmd_str(args, kwargs)[:200])
            t0 = time.time_ns()
            result = hooks._originals["subprocess_run"](*args, **kwargs)
            if hooks.events:
                hooks.events[-1].duration_ns = time.time_ns() - t0
                hooks.events[-1].result_preview = f"returncode={result.returncode}"
            return result

        _subprocess_mod.run = hooked_run

        original_popen_init = _subprocess_mod.Popen.__init__

        def hooked_popen_init(self_popen, *args, **kwargs):
            hooks._check_policy("subprocess", _cmd_str(args, kwargs)[:200])
            return original_popen_init(self_popen, *args, **kwargs)

        _subprocess_mod.Popen.__init__ = hooked_popen_init
        self._originals["Popen.__init__"] = original_popen_init

        def hooked_call(*a, **kw):
            hooks._check_policy("subprocess", _cmd_str(a, kw)[:200])
            return hooks._originals["subprocess_call"](*a, **kw)

        def hooked_check_output(*a, **kw):
            hooks._check_policy("subprocess", _cmd_str(a, kw)[:200])
            return hooks._originals["subprocess_check_output"](*a, **kw)

        def hooked_check_call(*a, **kw):
            hooks._check_policy("subprocess", _cmd_str(a, kw)[:200])
            return hooks._originals["subprocess_check_call"](*a, **kw)

        _subprocess_mod.call = hooked_call
        _subprocess_mod.check_output = hooked_check_output
        _subprocess_mod.check_call = hooked_check_call

        # ── Hook: os.system / os.popen ───────────────────────────
        self._originals["os_system"] = os.system

        def hooked_os_system(command):
            hooks._check_policy("os.system", str(command)[:200])
            return hooks._originals["os_system"](command)

        os.system = hooked_os_system

        self._originals["os_popen"] = os.popen

        def hooked_os_popen(command, *args, **kwargs):
            hooks._check_policy("os.system", f"popen: {str(command)[:200]}")
            return hooks._originals["os_popen"](command, *args, **kwargs)

        os.popen = hooked_os_popen

        # ── Hook: os.exec* family ────────────────────────────────
        _exec_funcs = [
            "execl",
            "execle",
            "execlp",
            "execlpe",
            "execv",
            "execve",
            "execvp",
            "execvpe",
        ]
        for fn_name in _exec_funcs:
            if hasattr(os, fn_name):
                self._originals[f"os_{fn_name}"] = getattr(os, fn_name)

                def make_hooked_exec(orig, name):
                    def hooked(*args, **kwargs):
                        cmd_str = " ".join(str(a) for a in args[:3])
                        hooks._check_policy("os.exec", f"{name}: {cmd_str[:200]}")
                        return orig(*args, **kwargs)

                    return hooked

                setattr(os, fn_name, make_hooked_exec(getattr(os, fn_name), fn_name))

        # Also hook os.spawn* if available
        _spawn_funcs = [
            "spawnl",
            "spawnle",
            "spawnlp",
            "spawnlpe",
            "spawnv",
            "spawnve",
            "spawnvp",
            "spawnvpe",
        ]
        for fn_name in _spawn_funcs:
            if hasattr(os, fn_name):
                self._originals[f"os_{fn_name}"] = getattr(os, fn_name)

                def make_hooked_spawn(orig, name):
                    def hooked(*args, **kwargs):
                        cmd_str = " ".join(str(a) for a in args[:4])
                        hooks._check_policy("os.exec", f"{name}: {cmd_str[:200]}")
                        return orig(*args, **kwargs)

                    return hooked

                setattr(os, fn_name, make_hooked_spawn(getattr(os, fn_name), fn_name))

        # ── Hook: socket.connect (network) ───────────────────────
        try:
            import socket

            self._originals["socket_connect"] = socket.socket.connect

            def hooked_connect(self_sock, address):
                addr_str = str(address)
                hooks._check_policy("network", f"connect → {addr_str}")
                return hooks._originals["socket_connect"](self_sock, address)

            socket.socket.connect = hooked_connect

            # Also hook socket.create_connection
            self._originals["socket_create_connection"] = socket.create_connection

            def hooked_create_connection(address, *args, **kwargs):
                hooks._check_policy("network", f"create_connection → {address}")
                return hooks._originals["socket_create_connection"](address, *args, **kwargs)

            socket.create_connection = hooked_create_connection
        except Exception:
            pass

        # ── Hook: urllib/requests/http.client ─────────────────────
        try:
            import urllib.request

            self._originals["urlopen"] = urllib.request.urlopen

            def hooked_urlopen(url, *args, **kwargs):
                url_str = str(url)[:200]
                hooks._check_policy("network", f"urlopen → {url_str}")
                t0 = time.time_ns()
                result = hooks._originals["urlopen"](url, *args, **kwargs)
                if hooks.events:
                    hooks.events[-1].duration_ns = time.time_ns() - t0
                return result

            urllib.request.urlopen = hooked_urlopen
        except Exception:
            pass

        try:
            import requests as _req

            self._originals["requests_request"] = _req.Session.request

            def hooked_request(self_session, method, url, *args, **kwargs):
                hooks._check_policy("network", f"{method} → {str(url)[:200]}")
                t0 = time.time_ns()
                result = hooks._originals["requests_request"](
                    self_session, method, url, *args, **kwargs
                )
                if hooks.events:
                    hooks.events[-1].duration_ns = time.time_ns() - t0
                    hooks.events[-1].result_preview = f"status={result.status_code}"
                return result

            _req.Session.request = hooked_request
        except ImportError:
            pass

        try:
            import http.client

            self._originals["http_connect"] = http.client.HTTPConnection.connect

            def hooked_http_connect(self_conn):
                hooks._check_policy("network", f"http.client → {self_conn.host}:{self_conn.port}")
                return hooks._originals["http_connect"](self_conn)

            http.client.HTTPConnection.connect = hooked_http_connect

            if hasattr(http.client, "HTTPSConnection"):
                self._originals["https_connect"] = http.client.HTTPSConnection.connect

                def hooked_https_connect(self_conn):
                    hooks._check_policy("network", f"https → {self_conn.host}:{self_conn.port}")
                    return hooks._originals["https_connect"](self_conn)

                http.client.HTTPSConnection.connect = hooked_https_connect
        except Exception:
            pass

        # ── Hook: __import__ + importlib.import_module ───────────
        self._originals["__import__"] = builtins.__import__

        def hooked_import(name, *args, **kwargs):
            if name not in sys.modules:
                hooks._check_policy("import", name)
            return hooks._originals["__import__"](name, *args, **kwargs)

        builtins.__import__ = hooked_import

        self._originals["importlib_import_module"] = _importlib_mod.import_module

        def hooked_import_module(name, package=None):
            full_name = name
            if name.startswith(".") and package:
                full_name = f"{package}{name}"
            if full_name not in sys.modules:
                hooks._check_policy("import", full_name)
            return hooks._originals["importlib_import_module"](name, package)

        _importlib_mod.import_module = hooked_import_module

        # ── Hook: os.link / os.symlink ───────────────────────────
        self._originals["os_link"] = os.link
        self._originals["os_symlink"] = os.symlink

        def hooked_os_link(src, dst, *args, **kwargs):
            hooks._check_policy("file.link", f"link {src} → {dst}")
            return hooks._originals["os_link"](src, dst, *args, **kwargs)

        def hooked_os_symlink(src, dst, *args, **kwargs):
            hooks._check_policy("file.link", f"symlink {src} → {dst}")
            return hooks._originals["os_symlink"](src, dst, *args, **kwargs)

        os.link = hooked_os_link
        os.symlink = hooked_os_symlink

        # ── Hook: os.mkdir / os.makedirs ─────────────────────────
        self._originals["os_mkdir"] = os.mkdir
        self._originals["os_makedirs"] = os.makedirs

        def hooked_os_mkdir(path, *args, **kwargs):
            hooks._check_policy("file.mkdir", str(path))
            return hooks._originals["os_mkdir"](path, *args, **kwargs)

        def hooked_os_makedirs(path, *args, **kwargs):
            hooks._check_policy("file.mkdir", f"makedirs {path}")
            return hooks._originals["os_makedirs"](path, *args, **kwargs)

        os.mkdir = hooked_os_mkdir
        os.makedirs = hooked_os_makedirs

        # ── Hook: os.read / os.write (low-level fd I/O) ─────────
        self._originals["os_read"] = os.read
        self._originals["os_write"] = os.write

        def hooked_os_read(fd, n, *args, **kwargs):
            hooks._check_policy("file.fd_io", f"os.read(fd={fd}, n={n})")
            return hooks._originals["os_read"](fd, n, *args, **kwargs)

        def hooked_os_write(fd, data, *args, **kwargs):
            hooks._check_policy("file.fd_io", f"os.write(fd={fd}, len={len(data)})")
            return hooks._originals["os_write"](fd, data, *args, **kwargs)

        os.read = hooked_os_read
        os.write = hooked_os_write

        # Hook os.truncate / os.ftruncate
        if hasattr(os, "truncate"):
            self._originals["os_truncate"] = os.truncate

            def hooked_os_truncate(path, length):
                hooks._check_policy("file.fd_io", f"truncate {path} to {length}")
                return hooks._originals["os_truncate"](path, length)

            os.truncate = hooked_os_truncate

        if hasattr(os, "ftruncate"):
            self._originals["os_ftruncate"] = os.ftruncate

            def hooked_os_ftruncate(fd, length):
                hooks._check_policy("file.fd_io", f"ftruncate fd={fd} to {length}")
                return hooks._originals["os_ftruncate"](fd, length)

            os.ftruncate = hooked_os_ftruncate

        # Hook os.sendfile
        if hasattr(os, "sendfile"):
            self._originals["os_sendfile"] = os.sendfile

            def hooked_os_sendfile(out_fd, in_fd, offset, count, *args, **kwargs):
                hooks._check_policy(
                    "file.fd_io", f"sendfile out_fd={out_fd} in_fd={in_fd} count={count}"
                )
                return hooks._originals["os_sendfile"](
                    out_fd, in_fd, offset, count, *args, **kwargs
                )

            os.sendfile = hooked_os_sendfile

        # ── Hook: os.mkfifo / os.mknod ───────────────────────────
        if hasattr(os, "mkfifo"):
            self._originals["os_mkfifo"] = os.mkfifo

            def hooked_os_mkfifo(path, *args, **kwargs):
                hooks._check_policy("file.special", f"mkfifo {path}")
                return hooks._originals["os_mkfifo"](path, *args, **kwargs)

            os.mkfifo = hooked_os_mkfifo

        if hasattr(os, "mknod"):
            self._originals["os_mknod"] = os.mknod

            def hooked_os_mknod(path, *args, **kwargs):
                hooks._check_policy("file.special", f"mknod {path}")
                return hooks._originals["os_mknod"](path, *args, **kwargs)

            os.mknod = hooked_os_mknod

        # ── Hook: socket.bind / listen / accept / send* ──────────
        try:
            import socket as _socket_mod

            self._originals["socket_bind"] = _socket_mod.socket.bind

            def hooked_bind(self_sock, address):
                hooks._check_policy("net.socket", f"bind → {address}")
                return hooks._originals["socket_bind"](self_sock, address)

            _socket_mod.socket.bind = hooked_bind

            self._originals["socket_listen"] = _socket_mod.socket.listen

            def hooked_listen(self_sock, backlog=None):
                hooks._check_policy("net.socket", f"listen backlog={backlog}")
                if backlog is not None:
                    return hooks._originals["socket_listen"](self_sock, backlog)
                return hooks._originals["socket_listen"](self_sock)

            _socket_mod.socket.listen = hooked_listen

            self._originals["socket_send"] = _socket_mod.socket.send

            def hooked_send(self_sock, data, *args, **kwargs):
                hooks._check_policy("net.socket", f"send {len(data)} bytes")
                return hooks._originals["socket_send"](self_sock, data, *args, **kwargs)

            _socket_mod.socket.send = hooked_send

            self._originals["socket_sendall"] = _socket_mod.socket.sendall

            def hooked_sendall(self_sock, data, *args, **kwargs):
                hooks._check_policy("net.socket", f"sendall {len(data)} bytes")
                return hooks._originals["socket_sendall"](self_sock, data, *args, **kwargs)

            _socket_mod.socket.sendall = hooked_sendall

            self._originals["socket_sendto"] = _socket_mod.socket.sendto

            def hooked_sendto(self_sock, data, *args, **kwargs):
                hooks._check_policy("net.socket", f"sendto {len(data)} bytes → {args}")
                return hooks._originals["socket_sendto"](self_sock, data, *args, **kwargs)

            _socket_mod.socket.sendto = hooked_sendto
        except Exception:
            pass

        # ── Hook: os.fork / os.forkpty ───────────────────────────
        if hasattr(os, "fork"):
            self._originals["os_fork"] = os.fork

            def hooked_os_fork():
                hooks._check_policy("process.fork", "os.fork()")
                return hooks._originals["os_fork"]()

            os.fork = hooked_os_fork

        if hasattr(os, "forkpty"):
            self._originals["os_forkpty"] = os.forkpty

            def hooked_os_forkpty():
                hooks._check_policy("process.fork", "os.forkpty()")
                return hooks._originals["os_forkpty"]()

            os.forkpty = hooked_os_forkpty

        # ── Hook: os.kill / os.killpg ────────────────────────────
        self._originals["os_kill"] = os.kill

        def hooked_os_kill(pid, sig):
            hooks._check_policy("process.kill", f"kill pid={pid} sig={sig}")
            return hooks._originals["os_kill"](pid, sig)

        os.kill = hooked_os_kill

        if hasattr(os, "killpg"):
            self._originals["os_killpg"] = os.killpg

            def hooked_os_killpg(pgid, sig):
                hooks._check_policy("process.kill", f"killpg pgid={pgid} sig={sig}")
                return hooks._originals["os_killpg"](pgid, sig)

            os.killpg = hooked_os_killpg

        # ── Hook: multiprocessing.Process ─────────────────────────
        try:
            import multiprocessing as _mp_mod

            self._originals["mp_Process_start"] = _mp_mod.Process.start

            def hooked_mp_start(self_proc):
                target = getattr(self_proc, "_target", None)
                name = getattr(self_proc, "name", "?")
                hooks._check_policy("process.mp", f"Process.start name={name} target={target}")
                return hooks._originals["mp_Process_start"](self_proc)

            _mp_mod.Process.start = hooked_mp_start
        except Exception:
            pass

        # ── Hook: ctypes (block FFI escape) ───────────────────────
        try:
            import ctypes as _ctypes_mod

            self._originals["ctypes_CDLL"] = _ctypes_mod.CDLL

            class HookedCDLL:
                def __new__(cls, name, *args, **kwargs):
                    hooks._check_policy("meta.ctypes", f"CDLL({name})")
                    return hooks._originals["ctypes_CDLL"](name, *args, **kwargs)

            _ctypes_mod.CDLL = HookedCDLL

            # Also hook ctypes.cdll attribute access
            if hasattr(_ctypes_mod, "cdll"):
                self._originals["ctypes_cdll_LoadLibrary"] = _ctypes_mod.cdll.LoadLibrary

                def hooked_LoadLibrary(name):
                    hooks._check_policy("meta.ctypes", f"cdll.LoadLibrary({name})")
                    return hooks._originals["ctypes_cdll_LoadLibrary"](name)

                _ctypes_mod.cdll.LoadLibrary = hooked_LoadLibrary
        except Exception:
            pass

        # ── Hook: eval / exec / compile (meta-execution) ─────────
        self._originals["builtins_eval"] = builtins.eval
        self._originals["builtins_exec"] = builtins.exec
        self._originals["builtins_compile"] = builtins.compile

        def hooked_eval(source, *args, **kwargs):
            src_preview = str(source)[:100]
            hooks._check_policy("meta.code", f"eval({src_preview})")
            return hooks._originals["builtins_eval"](source, *args, **kwargs)

        def hooked_exec(source, *args, **kwargs):
            src_preview = str(source)[:100]
            hooks._check_policy("meta.code", f"exec({src_preview})")
            return hooks._originals["builtins_exec"](source, *args, **kwargs)

        def hooked_compile(source, *args, **kwargs):
            src_preview = str(source)[:100]
            hooks._check_policy("meta.code", f"compile({src_preview})")
            return hooks._originals["builtins_compile"](source, *args, **kwargs)

        builtins.eval = hooked_eval
        builtins.exec = hooked_exec
        builtins.compile = hooked_compile

        self._installed = True

    def uninstall(self):
        """Restore all original syscalls."""
        if not self._installed:
            return

        # builtins
        if "open" in self._originals:
            builtins.open = self._originals["open"]
        if "__import__" in self._originals:
            builtins.__import__ = self._originals["__import__"]

        # os module
        _os_restores = [
            "os_open",
            "os_remove",
            "os_unlink",
            "os_rmdir",
            "os_removedirs",
            "os_rename",
            "os_replace",
            "os_renames",
            "os_chmod",
            "os_chown",
            "os_system",
            "os_popen",
        ]
        for key in _os_restores:
            if key in self._originals:
                attr_name = key.replace("os_", "", 1)
                try:
                    setattr(os, attr_name, self._originals[key])
                except (AttributeError, TypeError):
                    pass

        # os.exec* and os.spawn*
        for key, orig in self._originals.items():
            if key.startswith("os_exec") or key.startswith("os_spawn"):
                attr_name = key.replace("os_", "", 1)
                try:
                    setattr(os, attr_name, orig)
                except (AttributeError, TypeError):
                    pass

        # subprocess
        if "subprocess_run" in self._originals:
            _subprocess_mod.run = self._originals["subprocess_run"]
        if "Popen.__init__" in self._originals:
            _subprocess_mod.Popen.__init__ = self._originals["Popen.__init__"]
        if "subprocess_call" in self._originals:
            _subprocess_mod.call = self._originals["subprocess_call"]
        if "subprocess_check_output" in self._originals:
            _subprocess_mod.check_output = self._originals["subprocess_check_output"]
        if "subprocess_check_call" in self._originals:
            _subprocess_mod.check_call = self._originals["subprocess_check_call"]

        # shutil
        _shutil_restores = [
            "shutil_rmtree",
            "shutil_move",
            "shutil_copy",
            "shutil_copy2",
            "shutil_copytree",
        ]
        for key in _shutil_restores:
            if key in self._originals:
                attr_name = key.replace("shutil_", "", 1)
                try:
                    setattr(_shutil_mod, attr_name, self._originals[key])
                except (AttributeError, TypeError):
                    pass

        # socket
        try:
            import socket

            if "socket_connect" in self._originals:
                socket.socket.connect = self._originals["socket_connect"]
            if "socket_create_connection" in self._originals:
                socket.create_connection = self._originals["socket_create_connection"]
        except Exception:
            pass

        # urllib
        try:
            import urllib.request

            if "urlopen" in self._originals:
                urllib.request.urlopen = self._originals["urlopen"]
        except Exception:
            pass

        # requests
        try:
            import requests as _req

            if "requests_request" in self._originals:
                _req.Session.request = self._originals["requests_request"]
        except Exception:
            pass

        # http.client
        try:
            import http.client

            if "http_connect" in self._originals:
                http.client.HTTPConnection.connect = self._originals["http_connect"]
            if "https_connect" in self._originals:
                http.client.HTTPSConnection.connect = self._originals["https_connect"]
        except Exception:
            pass

        # importlib
        if "importlib_import_module" in self._originals:
            _importlib_mod.import_module = self._originals["importlib_import_module"]

        # os.link/symlink
        for key in ["os_link", "os_symlink"]:
            if key in self._originals:
                setattr(os, key.replace("os_", ""), self._originals[key])

        # os.mkdir/makedirs
        for key in ["os_mkdir", "os_makedirs"]:
            if key in self._originals:
                setattr(os, key.replace("os_", ""), self._originals[key])

        # os.read/write/truncate/ftruncate/sendfile
        for key in ["os_read", "os_write", "os_truncate", "os_ftruncate", "os_sendfile"]:
            if key in self._originals:
                setattr(os, key.replace("os_", ""), self._originals[key])

        # os.mkfifo/mknod
        for key in ["os_mkfifo", "os_mknod"]:
            if key in self._originals:
                setattr(os, key.replace("os_", ""), self._originals[key])

        # socket.bind/listen/send*
        try:
            import socket as _socket_mod

            for key in [
                "socket_bind",
                "socket_listen",
                "socket_send",
                "socket_sendall",
                "socket_sendto",
            ]:
                if key in self._originals:
                    attr = key.replace("socket_", "")
                    setattr(_socket_mod.socket, attr, self._originals[key])
        except Exception:
            pass

        # os.fork/forkpty/kill/killpg
        for key in ["os_fork", "os_forkpty", "os_kill", "os_killpg"]:
            if key in self._originals:
                setattr(os, key.replace("os_", ""), self._originals[key])

        # multiprocessing
        try:
            import multiprocessing as _mp_mod

            if "mp_Process_start" in self._originals:
                _mp_mod.Process.start = self._originals["mp_Process_start"]
        except Exception:
            pass

        # ctypes
        try:
            import ctypes as _ctypes_mod

            if "ctypes_CDLL" in self._originals:
                _ctypes_mod.CDLL = self._originals["ctypes_CDLL"]
            if "ctypes_cdll_LoadLibrary" in self._originals:
                _ctypes_mod.cdll.LoadLibrary = self._originals["ctypes_cdll_LoadLibrary"]
        except Exception:
            pass

        # eval/exec/compile
        if "builtins_eval" in self._originals:
            builtins.eval = self._originals["builtins_eval"]
        if "builtins_exec" in self._originals:
            builtins.exec = self._originals["builtins_exec"]
        if "builtins_compile" in self._originals:
            builtins.compile = self._originals["builtins_compile"]

        self._installed = False

    def get_stats(self) -> dict:
        """Get categorized syscall stats."""
        stats = {
            "files_read": [],
            "files_written": [],
            "files_deleted": [],
            "files_moved": [],
            "files_chmod": [],
            "files_linked": [],
            "files_mkdir": [],
            "files_fd_io": [],
            "files_special": [],
            "network_calls": [],
            "net_socket": [],
            "subprocesses": [],
            "os_system_calls": [],
            "os_exec_calls": [],
            "process_fork": [],
            "process_kill": [],
            "process_mp": [],
            "imports": [],
            "meta_ctypes": [],
            "meta_code": [],
            "denied": [],
        }
        for e in self.events:
            d = e.to_dict()
            if e.decision == "deny":
                stats["denied"].append(d)
            if e.action == "file.read":
                stats["files_read"].append(e.detail)
            elif e.action == "file.write":
                stats["files_written"].append(e.detail)
            elif e.action == "file.delete":
                stats["files_deleted"].append(e.detail)
            elif e.action == "file.move":
                stats["files_moved"].append(e.detail)
            elif e.action == "file.chmod":
                stats["files_chmod"].append(e.detail)
            elif e.action == "network":
                stats["network_calls"].append(e.detail)
            elif e.action == "subprocess":
                stats["subprocesses"].append(e.detail)
            elif e.action == "os.system":
                stats["os_system_calls"].append(e.detail)
            elif e.action == "os.exec":
                stats["os_exec_calls"].append(e.detail)
            elif e.action == "file.link":
                stats["files_linked"].append(e.detail)
            elif e.action == "file.mkdir":
                stats["files_mkdir"].append(e.detail)
            elif e.action == "file.fd_io":
                stats["files_fd_io"].append(e.detail)
            elif e.action == "file.special":
                stats["files_special"].append(e.detail)
            elif e.action == "net.socket":
                stats["net_socket"].append(e.detail)
            elif e.action == "process.fork":
                stats["process_fork"].append(e.detail)
            elif e.action == "process.kill":
                stats["process_kill"].append(e.detail)
            elif e.action == "process.mp":
                stats["process_mp"].append(e.detail)
            elif e.action == "import":
                stats["imports"].append(e.detail)
            elif e.action == "meta.ctypes":
                stats["meta_ctypes"].append(e.detail)
            elif e.action == "meta.code":
                stats["meta_code"].append(e.detail)
        return stats


# ─── Memory Sampler ─────────────────────────────────────────────────


class _MemSampler:
    def __init__(self, interval_ms=50):
        self.interval = interval_ms / 1000.0
        self.samples = []
        self._running = False
        self._t = None

    def start(self):
        self._running = True
        self._t = threading.Thread(target=self._loop, daemon=True)
        self._t.start()

    def stop(self):
        self._running = False
        if self._t:
            self._t.join(timeout=2)

    def _loop(self):
        t0 = time.monotonic()
        while self._running:
            cur, peak = tracemalloc.get_traced_memory()
            self.samples.append(
                {
                    "time_ms": round((time.monotonic() - t0) * 1000, 1),
                    "current_kb": round(cur / 1024, 1),
                    "peak_kb": round(peak / 1024, 1),
                }
            )
            time.sleep(self.interval)


# ─── The @inspect Decorator ────────────────────────────────────────


def watch(
    func: Callable = None,
    *,
    policy: Union[str, dict, Callable] = "allow_all",
    dump: bool = True,
    dump_dir: str = None,
    profile: bool = True,
    print_summary: bool = True,
    timeline_interval_ms: int = 50,
):
    """Decorator that records + sandboxes a function execution.

    Args:
        func: The function to decorate (used when @inspect without parens)
        policy: Syscall policy. Can be:
            - str: Built-in policy name ("allow_all", "deny_all", "deny_network",
                   "deny_write", "sandbox", "strict")
            - dict: Per-category policy. Keys are categories, values are:
                - str: "allow", "deny", "log", "ask"
                - callable: fn(action, detail) → "allow"|"deny"|"log"
                - dict: {"action": "allow|deny|log", "paths": [...], "hosts": [...], "packages": [...]}
            - callable: Global policy fn(action, detail) → "allow"|"deny"|"log"

        dump: Save .dill session file (default: True)
        dump_dir: Directory for dumps (default: ~/.strands_inspect/)
        profile: Enable memory/CPU profiling (default: True)
        print_summary: Print summary after execution (default: True)
        timeline_interval_ms: Memory sampling interval (default: 50ms)

    Categories:
        file.read, file.write, file.delete, file.move, file.chmod,
        network, subprocess, os.system, os.exec, import

    Examples:
        @inspect                              # log everything
        @watch(policy="deny_all")           # block everything
        @watch(policy="sandbox")            # block writes + network + subprocess
        @watch(policy={                     # granular control
            "file.read": {"action": "allow", "paths": ["/tmp/**"]},
            "file.write": "deny",
            "network": {"action": "allow", "hosts": ["api.openai.com"]},
            "import": {"action": "allow", "packages": ["json", "math"]},
        })
        @watch(policy={                     # callable per-category
            "network": lambda a, d: "allow" if "openai" in d else "deny",
        })
    """

    def decorator(fn: Callable) -> Callable:
        import inspect as _insp

        is_async = _insp.iscoroutinefunction(fn)

        def _setup(fn, args, kwargs):
            """Shared setup for sync and async wrappers."""
            if isinstance(policy, str):
                # Check built-in policies first, then config-defined named policies
                if policy in BUILTIN_POLICIES:
                    resolved_policy = BUILTIN_POLICIES[policy].copy()
                else:
                    named = get_named_policy(policy)
                    resolved_policy = dict(named) if named else BUILTIN_POLICIES["allow_all"].copy()
            elif callable(policy) and not isinstance(policy, dict):
                resolved_policy = {cat: policy for cat in ALL_CATEGORIES}
            else:
                resolved_policy = dict(policy)

            session = InspectSession(
                func_name=fn.__name__,
                func_module=getattr(fn, "__module__", "__main__"),
            )
            session.args = args
            session.kwargs = kwargs
            session.policy = {
                k: str(v) if not callable(v) else "<callable>" for k, v in resolved_policy.items()
            }
            session._func = fn

            try:
                import inspect as _inspect

                session.source_code = _inspect.getsource(fn)
            except (OSError, TypeError):
                session.source_code = ""

            hooks = SyscallHooks(resolved_policy)
            hooks.install()

            sampler = None
            was_tracing = tracemalloc.is_tracing()
            if profile:
                if was_tracing:
                    tracemalloc.stop()
                tracemalloc.start(10)
                sampler = _MemSampler(timeline_interval_ms)
                sampler.start()

            old_out, old_err = sys.stdout, sys.stderr
            cap_out, cap_err = io.StringIO(), io.StringIO()
            sys.stdout, sys.stderr = cap_out, cap_err

            return (
                session,
                hooks,
                sampler,
                was_tracing,
                old_out,
                old_err,
                cap_out,
                cap_err,
                resolved_policy,
            )

        def _teardown(session, hooks, sampler, was_tracing, old_out, old_err, cap_out, cap_err, t0):
            """Shared teardown for sync and async wrappers."""
            sys.stdout, sys.stderr = old_out, old_err
            session.stdout = cap_out.getvalue()
            session.stderr = cap_err.getvalue()
            session.wall_time_ms = round((time.perf_counter() - t0) * 1000, 2)

            if profile:
                if sampler:
                    sampler.stop()
                    session.memory_timeline = sampler.samples
                cur, peak = tracemalloc.get_traced_memory()
                session.memory_peak_kb = round(peak / 1024, 2)
                snap = tracemalloc.take_snapshot()
                for stat in snap.statistics("lineno")[:20]:
                    frame = stat.traceback[0]
                    session.memory_allocations.append(
                        {
                            "file": frame.filename,
                            "line": frame.lineno,
                            "size_kb": round(stat.size / 1024, 2),
                            "count": stat.count,
                        }
                    )
                if not was_tracing:
                    tracemalloc.stop()

            hooks.uninstall()

            session.syscalls = [e.to_dict() for e in hooks.events]
            stats = hooks.get_stats()
            session.files_read = stats["files_read"]
            session.files_written = stats["files_written"]
            session.files_deleted = stats["files_deleted"]
            session.files_moved = stats["files_moved"]
            session.files_chmod = stats["files_chmod"]
            session.network_calls = stats["network_calls"]
            session.subprocesses = stats["subprocesses"]
            session.os_system_calls = stats["os_system_calls"]
            session.os_exec_calls = stats["os_exec_calls"]
            session.imports = stats["imports"]
            session.denied = stats["denied"]

            dump_path = None
            if dump:
                target_dir = Path(dump_dir) if dump_dir else DUMP_DIR
                target_dir.mkdir(parents=True, exist_ok=True)
                dump_path = target_dir / f"{session.session_id}.dill"
                try:
                    with open(str(dump_path), "wb") as f:
                        _SERIALIZER.dump(session, f)
                except Exception:
                    session._func = None
                    try:
                        with open(str(dump_path), "wb") as f:
                            _SERIALIZER.dump(session, f)
                    except Exception:
                        dump_path = None

            if print_summary:
                print(session.summary())
                if dump_path:
                    print(f"   💾 Dump: {dump_path}")
                    print(
                        f"   🔄 Replay: `from strands_inspect import replay; s = replay('{dump_path}')`"
                    )

            return session, dump_path

        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            session, hooks, sampler, was_tracing, old_out, old_err, cap_out, cap_err, _ = _setup(
                fn, args, kwargs
            )
            t0 = time.perf_counter()
            result = None
            try:
                result = fn(*args, **kwargs)
                session.return_value = result
            except PolicyViolation as pv:
                session.exception = str(pv)
            except Exception as e:
                session.exception = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            finally:
                session, dump_path = _teardown(
                    session, hooks, sampler, was_tracing, old_out, old_err, cap_out, cap_err, t0
                )

            if result is not None and not isinstance(result, (int, float, str, bool, bytes)):
                try:
                    result.__inspect_session__ = session
                except (AttributeError, TypeError):
                    pass

            chosen.__last_session__ = session
            chosen.__last_dump__ = str(dump_path) if dump_path else None
            return result

        @functools.wraps(fn)
        async def async_wrapper(*args, **kwargs):
            session, hooks, sampler, was_tracing, old_out, old_err, cap_out, cap_err, _ = _setup(
                fn, args, kwargs
            )
            t0 = time.perf_counter()
            result = None
            try:
                result = await fn(*args, **kwargs)
                session.return_value = result
            except PolicyViolation as pv:
                session.exception = str(pv)
            except Exception as e:
                session.exception = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
            finally:
                session, dump_path = _teardown(
                    session, hooks, sampler, was_tracing, old_out, old_err, cap_out, cap_err, t0
                )

            if result is not None and not isinstance(result, (int, float, str, bool, bytes)):
                try:
                    result.__inspect_session__ = session
                except (AttributeError, TypeError):
                    pass

            chosen.__last_session__ = session
            chosen.__last_dump__ = str(dump_path) if dump_path else None
            return result

        chosen = async_wrapper if is_async else wrapper
        chosen.__inspected__ = True
        chosen.__last_session__ = None
        chosen.__last_dump__ = None

        return chosen

    if func is not None:
        return decorator(func)
    return decorator


# ─── Replay ─────────────────────────────────────────────────────────


def replay(path: str) -> InspectSession:
    """Load a recorded session from a .dill file.

    Args:
        path: Path to the .dill dump file

    Returns:
        InspectSession with full recorded state

    Example:
        session = replay("my_function_20260302_035500.dill")
        print(session.summary())
        print(session.syscalls)
        session.re_run()
    """
    path = os.path.expanduser(path)
    with open(path, "rb") as f:
        session = _SERIALIZER.load(f)
    return session


def list_sessions(dump_dir: str = None) -> List[dict]:
    """List all recorded sessions."""
    target = Path(dump_dir) if dump_dir else DUMP_DIR
    sessions = []
    for f in sorted(target.glob("*.dill"), reverse=True):
        stat = f.stat()
        sessions.append(
            {
                "path": str(f),
                "name": f.stem,
                "size_kb": round(stat.st_size / 1024, 1),
                "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            }
        )
    return sessions

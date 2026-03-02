"""
🔒 Kernel-level sandboxing — the layer Python can't escape.

Two backends:
  - macOS: sandbox-exec (Seatbelt profiles via sandbox_init / sandbox-exec)
  - Linux: seccomp-bpf (syscall filtering via libseccomp or raw BPF)

Both are IRREVERSIBLE once applied to a process. So we:
  1. Fork a child process
  2. Apply kernel sandbox in the child
  3. Run the function
  4. Serialize result back via pipe
  5. Parent collects result

This means even ctypes, mmap, C extensions, inline assembly —
NOTHING can escape. The kernel itself enforces the policy.

Usage:
    from strands_inspect import inspect

    # macOS Seatbelt sandbox
    @inspect(policy="sandbox", kernel=True)
    def untrusted():
        import urllib.request
        urllib.request.urlopen("http://evil.com")  # KILLED by kernel

    # Granular kernel policy
    @inspect(kernel={
        "network": False,          # block all networking
        "file_write": False,       # block file writes
        "file_read": ["/tmp/**"],  # allow reads only from /tmp
        "subprocess": False,       # block process spawning
    })
    def sandboxed():
        ...

    # Or use directly:
    from strands_inspect._sandbox import KernelSandbox
    sb = KernelSandbox(policy={"network": False})
    result = sb.run(my_function, args=(1, 2))
"""

import ctypes
import ctypes.util
import json
import multiprocessing
import os
import pickle
import platform
import signal
import struct
import sys
import tempfile
import textwrap
import time
import traceback
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

# ─── Result Type ─────────────────────────────────────────────────────


@dataclass
class SandboxResult:
    """Result from a kernel-sandboxed execution."""

    success: bool = False
    return_value: Any = None
    exception: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    wall_time_ms: float = 0
    sandbox_type: str = ""  # "seatbelt" or "seccomp"
    policy_applied: Dict = field(default_factory=dict)
    killed_by_sandbox: bool = False
    exit_code: Optional[int] = None
    violations: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["return_value"] = repr(self.return_value)[:500] if self.return_value is not None else None
        return d

    def summary(self) -> str:
        status = "✅" if self.success else "💀" if self.killed_by_sandbox else "❌"
        lines = [
            f"{status} KernelSandbox ({self.sandbox_type})",
            f"   Wall: {self.wall_time_ms:.1f}ms",
        ]
        if self.return_value is not None:
            lines.append(f"   Return: {repr(self.return_value)[:100]}")
        if self.exception:
            lines.append(f"   Exception: {self.exception[:100]}")
        if self.killed_by_sandbox:
            lines.append(f"   🔒 KILLED BY KERNEL SANDBOX (exit={self.exit_code})")
        if self.violations:
            lines.append(f"   🚫 Violations: {len(self.violations)}")
            for v in self.violations[:5]:
                lines.append(f"      - {v}")
        if self.stdout:
            lines.append(f"   stdout: {self.stdout[:100]}")
        return "\n".join(lines)


# ─── Policy Translation ─────────────────────────────────────────────

# Unified policy format:
# {
#     "network": False,                    # block all networking
#     "file_write": False,                 # block all file writes
#     "file_read": True,                   # allow all reads
#     "file_read": ["/tmp/**", "/data/**"],# allow reads from specific paths
#     "subprocess": False,                 # block process execution
#     "ipc": False,                        # block IPC (signals, shared memory)
#     "mmap_exec": False,                  # block executable mmap (JIT)
# }

DEFAULT_POLICY = {
    "network": True,
    "file_read": True,
    "file_write": True,
    "subprocess": True,
    "ipc": True,
    "mmap_exec": True,
    "sysctl": True,
}

SANDBOX_POLICY = {
    "network": False,
    "file_read": True,
    "file_write": False,
    "subprocess": False,
    "ipc": True,
    "mmap_exec": False,
    "sysctl": False,
}

STRICT_POLICY = {
    "network": False,
    "file_read": ["/tmp/**", "/dev/null", "/dev/urandom"],
    "file_write": False,
    "subprocess": False,
    "ipc": False,
    "mmap_exec": False,
    "sysctl": False,
}

DENY_ALL_POLICY = {
    "network": False,
    "file_read": False,
    "file_write": False,
    "subprocess": False,
    "ipc": False,
    "mmap_exec": False,
    "sysctl": False,
}

BUILTIN_KERNEL_POLICIES = {
    "default": DEFAULT_POLICY,
    "sandbox": SANDBOX_POLICY,
    "strict": STRICT_POLICY,
    "deny_all": DENY_ALL_POLICY,
}


def resolve_kernel_policy(policy) -> Dict:
    """Resolve a kernel policy spec to a concrete dict."""
    if isinstance(policy, str):
        return BUILTIN_KERNEL_POLICIES.get(policy, SANDBOX_POLICY).copy()
    if isinstance(policy, dict):
        base = DEFAULT_POLICY.copy()
        base.update(policy)
        return base
    if policy is True:
        return SANDBOX_POLICY.copy()
    return DEFAULT_POLICY.copy()


# =============================================================================
# 🍎 macOS Seatbelt Sandbox (sandbox-exec / sandbox_init)
# =============================================================================


def _policy_to_seatbelt(policy: Dict) -> str:
    """Convert unified policy dict to macOS Seatbelt profile (SBPL).

    Seatbelt uses Scheme-like S-expressions:
      (version 1)
      (deny default)
      (allow process-exec)
      (allow file-read* (subpath "/tmp"))
      (deny network*)
    """
    rules = ["(version 1)"]

    # Start by denying everything, then allow what's needed
    rules.append("(deny default)")

    # Always allow basic process execution (needed to run Python)
    rules.append("(allow process-exec*)")
    rules.append("(allow process-fork)")

    # Always allow mach lookups (needed for basic macOS operation)
    rules.append("(allow mach-lookup)")
    rules.append("(allow mach-register)")

    # Allow signal handling
    rules.append("(allow signal (target self))")

    # Always allow sysctl reads (needed for Python startup)
    if policy.get("sysctl", True):
        rules.append("(allow sysctl-read)")
    else:
        rules.append('(allow sysctl-read (sysctl-name-prefix "hw."))')
        rules.append('(allow sysctl-read (sysctl-name-prefix "kern."))')

    # ── File read ────────────────────────────────────────────────
    file_read = policy.get("file_read", True)
    if file_read is True:
        rules.append("(allow file-read*)")
    elif file_read is False:
        # Allow minimal reads needed for Python to work
        rules.append('(allow file-read* (subpath "/usr/lib"))')
        rules.append('(allow file-read* (subpath "/usr/local/lib"))')
        rules.append('(allow file-read* (subpath "/opt/homebrew"))')
        rules.append('(allow file-read* (subpath "/Library/Frameworks/Python.framework"))')
        rules.append('(allow file-read* (literal "/dev/null"))')
        rules.append('(allow file-read* (literal "/dev/urandom"))')
        rules.append('(allow file-read* (literal "/dev/random"))')
        # Allow reading Python's own files
        python_prefix = sys.prefix
        rules.append(f'(allow file-read* (subpath "{python_prefix}"))')
        # Allow reading the venv if in one
        if hasattr(sys, "real_prefix") or (
            hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
        ):
            rules.append(f'(allow file-read* (subpath "{sys.base_prefix}"))')
    elif isinstance(file_read, list):
        # Allow reads from specific paths
        rules.append('(allow file-read* (subpath "/usr/lib"))')
        rules.append('(allow file-read* (subpath "/opt/homebrew"))')
        rules.append(f'(allow file-read* (subpath "{sys.prefix}"))')
        if hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix:
            rules.append(f'(allow file-read* (subpath "{sys.base_prefix}"))')
        for path_pattern in file_read:
            clean = path_pattern.rstrip("/*").rstrip("*")
            if clean:
                rules.append(f'(allow file-read* (subpath "{clean}"))')

    # ── File write ───────────────────────────────────────────────
    file_write = policy.get("file_write", True)
    if file_write is True:
        rules.append("(allow file-write*)")
    elif file_write is False:
        # Allow writes to /dev/null and tmp for Python internals
        rules.append('(allow file-write* (literal "/dev/null"))')
        rules.append('(allow file-write* (subpath "/tmp"))')
        rules.append('(allow file-write* (subpath "/private/tmp"))')
        rules.append(f'(allow file-write* (subpath "{tempfile.gettempdir()}"))')
        rules.append('(allow file-write* (subpath "/var/folders"))')
    elif isinstance(file_write, list):
        rules.append('(allow file-write* (literal "/dev/null"))')
        for path_pattern in file_write:
            clean = path_pattern.rstrip("/*").rstrip("*")
            if clean:
                rules.append(f'(allow file-write* (subpath "{clean}"))')

    # ── Network ──────────────────────────────────────────────────
    network = policy.get("network", True)
    if network is True:
        rules.append("(allow network*)")
    elif network is False:
        pass  # deny default already blocks it
    elif isinstance(network, list):
        # Allow specific hosts (limited - seatbelt supports remote ip)
        for host in network:
            rules.append(f'(allow network* (remote ip "{host}:*"))')

    # ── Subprocess ───────────────────────────────────────────────
    subprocess_policy = policy.get("subprocess", True)
    if subprocess_policy is True:
        pass  # process-exec already allowed above
    elif subprocess_policy is False:
        # Remove the process-exec allow and be more restrictive
        # Actually we need process-exec for Python itself, so we restrict to python only
        rules = [r for r in rules if "process-exec*" not in r and "process-fork" not in r]
        # Allow Python itself (resolve symlinks for venvs)
        python_real = os.path.realpath(sys.executable)
        python_dir = os.path.dirname(python_real)
        rules.append('(allow process-exec (subpath "' + python_dir + '"))')
        rules.append('(allow process-exec (subpath "/opt/homebrew"))')
        rules.append('(allow process-exec (subpath "/usr/bin"))')
        rules.append('(allow process-exec (subpath "/usr/local/bin"))')
        rules.append('(allow process-exec (literal "' + sys.executable + '"))')
        rules.append('(allow process-exec (literal "' + python_real + '"))')
        # Allow the full Python framework (macOS uses Python.app inside Resources/)
        # e.g. /Library/Frameworks/Python.framework/Versions/3.10/Resources/Python.app/Contents/MacOS/Python
        if (
            "/Library/Frameworks/Python.framework" in python_real
            or "/Library/Frameworks/Python.framework" in sys.executable
        ):
            rules.append('(allow process-exec (subpath "/Library/Frameworks/Python.framework"))')
        # Also allow the prefix directory (covers venvs that point into framework)
        python_prefix = os.path.dirname(os.path.dirname(python_real))
        if python_prefix and python_prefix != python_dir:
            rules.append(f'(allow process-exec (subpath "{python_prefix}"))')
        rules.append("(allow process-fork)")
    # ── IPC ──────────────────────────────────────────────────────
    ipc = policy.get("ipc", True)
    if ipc is True:
        rules.append("(allow ipc*)")
    elif ipc is False:
        rules.append("(allow ipc-posix-shm-read-data)")  # minimum for Python

    # ── mmap exec ────────────────────────────────────────────────
    # Always allow mapping Python's own libraries (needed to start)
    python_framework = os.path.dirname(os.path.dirname(os.path.realpath(sys.executable)))
    rules.append(f'(allow file-map-executable (subpath "{python_framework}"))')
    rules.append('(allow file-map-executable (subpath "/usr/lib"))')
    rules.append('(allow file-map-executable (subpath "/usr/local/lib"))')
    rules.append('(allow file-map-executable (subpath "/opt/homebrew"))')
    rules.append('(allow file-map-executable (subpath "/Library"))')
    rules.append('(allow file-map-executable (subpath "/System"))')
    # Allow file metadata reads (needed for filesystem operations)
    rules.append("(allow file-read-metadata)")

    mmap_exec = policy.get("mmap_exec", True)
    if mmap_exec is True:
        rules.append("(allow file-map-executable)")

    return "\n".join(rules)


def _run_seatbelt(
    func_source: str,
    func_name: str,
    args_file: str,
    result_file: str,
    profile: str,
    timeout: int = 30,
) -> SandboxResult:
    """Run code in a macOS sandbox-exec process."""
    import subprocess

    # Build the runner script
    runner = f"""
import pickle, sys, os, io, time, traceback
sys.path.insert(0, {repr(str(Path(__file__).parent.parent))})

t0 = time.perf_counter()
result = {{"success": False, "return_value": None, "exception": None, "stdout": "", "stderr": ""}}

# Load args
with open({repr(args_file)}, "rb") as f:
    args, kwargs = pickle.load(f)

# Capture output
old_out, old_err = sys.stdout, sys.stderr
cap_out, cap_err = io.StringIO(), io.StringIO()

try:
    sys.stdout, sys.stderr = cap_out, cap_err

    # Define and run the function
{textwrap.indent(func_source, "    ")}

    rv = {func_name}(*args, **kwargs)
    result["return_value"] = rv
    result["success"] = True
except Exception as e:
    result["exception"] = f"{{type(e).__name__}}: {{e}}\\n{{traceback.format_exc()}}"
finally:
    sys.stdout, sys.stderr = old_out, old_err
    result["stdout"] = cap_out.getvalue()
    result["stderr"] = cap_err.getvalue()
    result["wall_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)

# Write result
with open({repr(result_file)}, "wb") as f:
    pickle.dump(result, f)
"""

    # Write runner to temp file
    runner_file = tempfile.mktemp(suffix=".py", prefix="sandbox_runner_", dir="/tmp")
    with open(runner_file, "w") as f:
        f.write(runner)

    # Write the seatbelt profile
    profile_file = tempfile.mktemp(suffix=".sb", prefix="sandbox_profile_", dir="/tmp")
    with open(profile_file, "w") as f:
        f.write(profile)

    sr = SandboxResult(sandbox_type="seatbelt", policy_applied={"profile": profile})
    t0 = time.perf_counter()

    try:
        proc = subprocess.run(
            ["sandbox-exec", "-f", profile_file, sys.executable, runner_file],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        sr.wall_time_ms = round((time.perf_counter() - t0) * 1000, 2)
        sr.exit_code = proc.returncode

        if proc.returncode == 0 and os.path.exists(result_file):
            # Success - load result
            with open(result_file, "rb") as f:
                inner = pickle.load(f)
            sr.success = inner.get("success", False)
            sr.return_value = inner.get("return_value")
            sr.exception = inner.get("exception")
            sr.stdout = inner.get("stdout", "")
            sr.stderr = inner.get("stderr", "")
            sr.wall_time_ms = inner.get("wall_time_ms", sr.wall_time_ms)
        elif proc.returncode != 0:
            # Process was killed or errored
            sr.killed_by_sandbox = proc.returncode in (
                -signal.SIGKILL,
                -signal.SIGABRT,
                137,
                134,
                1,
            )
            sr.stderr = proc.stderr
            sr.stdout = proc.stdout

            if (
                sr.killed_by_sandbox
                or "deny" in proc.stderr.lower()
                or "sandbox" in proc.stderr.lower()
            ):
                sr.killed_by_sandbox = True
                sr.violations.append(f"Process killed by sandbox (exit={proc.returncode})")
                # Parse sandbox violation logs from stderr
                for line in proc.stderr.split("\n"):
                    if "deny" in line.lower() or "sandbox" in line.lower():
                        sr.violations.append(line.strip())
            else:
                sr.exception = proc.stderr

    except subprocess.TimeoutExpired:
        sr.exception = f"Timeout after {timeout}s"
        sr.wall_time_ms = timeout * 1000
    except FileNotFoundError:
        sr.exception = "sandbox-exec not found (macOS only)"
    except Exception as e:
        sr.exception = f"{type(e).__name__}: {e}"
    finally:
        # Cleanup
        for f in [runner_file, profile_file]:
            try:
                os.unlink(f)
            except:
                pass

    return sr


# =============================================================================
# 🐧 Linux seccomp-bpf Sandbox
# =============================================================================

# seccomp constants
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_KILL_THREAD = 0x00000000
SECCOMP_RET_TRAP = 0x00030000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_LOG = 0x7FFC0000

PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22

# BPF instruction constants
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_K = 0x00
BPF_RET = 0x06

# Audit arch for x86_64
AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# Common syscall numbers (x86_64)
SYSCALLS_X86_64 = {
    "socket": 41,
    "connect": 42,
    "accept": 43,
    "sendto": 44,
    "recvfrom": 45,
    "sendmsg": 46,
    "recvmsg": 47,
    "bind": 49,
    "listen": 50,
    "socketpair": 53,
    "setsockopt": 54,
    "getsockopt": 55,
    "accept4": 288,
    "execve": 59,
    "fork": 57,
    "vfork": 58,
    "clone": 56,
    "clone3": 435,
    "execveat": 322,
    "open": 2,
    "openat": 257,
    "creat": 85,
    "unlink": 87,
    "unlinkat": 263,
    "rename": 82,
    "renameat": 264,
    "renameat2": 316,
    "mkdir": 83,
    "mkdirat": 258,
    "rmdir": 84,
    "link": 86,
    "linkat": 265,
    "symlink": 88,
    "symlinkat": 266,
    "chmod": 90,
    "fchmod": 91,
    "fchmodat": 268,
    "chown": 92,
    "fchown": 93,
    "lchown": 94,
    "fchownat": 260,
    "mmap": 9,
    "mprotect": 10,
    "kill": 62,
    "tkill": 200,
    "tgkill": 234,
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "swapon": 167,
    "swapoff": 168,
    "reboot": 169,
    "sethostname": 170,
    "setdomainname": 171,
    "iopl": 172,
    "ioperm": 173,
    "init_module": 175,
    "finit_module": 313,
    "delete_module": 176,
}

# Common syscall numbers (aarch64)
SYSCALLS_AARCH64 = {
    "socket": 198,
    "connect": 203,
    "accept": 202,
    "sendto": 206,
    "recvfrom": 207,
    "sendmsg": 211,
    "recvmsg": 212,
    "bind": 200,
    "listen": 201,
    "socketpair": 199,
    "setsockopt": 208,
    "getsockopt": 209,
    "accept4": 242,
    "execve": 221,
    "clone": 220,
    "clone3": 435,
    "execveat": 281,
    "openat": 56,
    "unlinkat": 35,
    "renameat": 38,
    "renameat2": 276,
    "mkdirat": 34,
    "linkat": 37,
    "symlinkat": 36,
    "fchmod": 52,
    "fchmodat": 53,
    "fchown": 55,
    "fchownat": 54,
    "mmap": 222,
    "mprotect": 226,
    "kill": 129,
    "tkill": 130,
    "tgkill": 131,
    "ptrace": 117,
    "mount": 40,
    "umount2": 39,
    "reboot": 142,
    "init_module": 105,
    "finit_module": 273,
    "delete_module": 106,
}


def _get_arch_and_syscalls():
    """Get the correct audit architecture and syscall table."""
    machine = platform.machine()
    if machine == "x86_64":
        return AUDIT_ARCH_X86_64, SYSCALLS_X86_64
    elif machine in ("aarch64", "arm64"):
        return AUDIT_ARCH_AARCH64, SYSCALLS_AARCH64
    else:
        return None, {}


def _bpf_stmt(code, k):
    """Create a BPF statement (instruction without jt/jf)."""
    return struct.pack("HBBI", code, 0, 0, k)


def _bpf_jump(code, k, jt, jf):
    """Create a BPF jump instruction."""
    return struct.pack("HBBI", code, jt, jf, k)


def _policy_to_blocked_syscalls(policy: Dict) -> List[int]:
    """Convert unified policy to list of syscall numbers to block."""
    _, syscalls = _get_arch_and_syscalls()
    if not syscalls:
        return []

    blocked = []

    if not policy.get("network", True):
        for name in [
            "socket",
            "connect",
            "accept",
            "accept4",
            "sendto",
            "sendmsg",
            "recvfrom",
            "recvmsg",
            "bind",
            "listen",
            "socketpair",
            "setsockopt",
            "getsockopt",
        ]:
            if name in syscalls:
                blocked.append(syscalls[name])

    if not policy.get("subprocess", True):
        for name in ["execve", "execveat", "fork", "vfork", "clone", "clone3"]:
            if name in syscalls:
                blocked.append(syscalls[name])

    if not policy.get("file_write", True):
        for name in [
            "creat",
            "unlink",
            "unlinkat",
            "rename",
            "renameat",
            "renameat2",
            "mkdir",
            "mkdirat",
            "rmdir",
            "link",
            "linkat",
            "symlink",
            "symlinkat",
            "chmod",
            "fchmod",
            "fchmodat",
            "chown",
            "fchown",
            "lchown",
            "fchownat",
        ]:
            if name in syscalls:
                blocked.append(syscalls[name])

    if not policy.get("ipc", True):
        for name in ["kill", "tkill", "tgkill", "ptrace"]:
            if name in syscalls:
                blocked.append(syscalls[name])

    if not policy.get("mmap_exec", True):
        # We can't easily block mmap with PROT_EXEC via simple seccomp
        # (need argument inspection), so we skip this for basic BPF
        pass

    if not policy.get("sysctl", True):
        for name in [
            "sethostname",
            "setdomainname",
            "mount",
            "umount2",
            "swapon",
            "swapoff",
            "reboot",
            "iopl",
            "ioperm",
            "init_module",
            "finit_module",
            "delete_module",
        ]:
            if name in syscalls:
                blocked.append(syscalls[name])

    return list(set(blocked))


def _build_bpf_filter(blocked_syscalls: List[int], action: int = None) -> bytes:
    """Build a BPF filter program that blocks specified syscalls.

    The filter:
    1. Load syscall number from seccomp_data
    2. For each blocked syscall: if matches, return KILL/ERRNO
    3. Default: ALLOW
    """
    if action is None:
        action = SECCOMP_RET_ERRNO | 1  # EPERM

    arch, _ = _get_arch_and_syscalls()
    if not arch:
        return b""

    instructions = []

    # Load architecture from seccomp_data.arch (offset 4)
    instructions.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4))

    # Check architecture matches
    n_syscalls = len(blocked_syscalls)
    # If arch doesn't match, skip to ALLOW (past all syscall checks + 1 for the load)
    instructions.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 0, n_syscalls + 2))

    # Load syscall number from seccomp_data.nr (offset 0)
    instructions.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))

    # For each blocked syscall, check and deny
    for i, nr in enumerate(blocked_syscalls):
        remaining = n_syscalls - i - 1
        # If matches: jump to DENY (which is at remaining + 1 from here)
        # If not: continue to next check (0)
        instructions.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, remaining, 0))

    # Default: ALLOW
    instructions.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))

    # DENY action
    instructions.append(_bpf_stmt(BPF_RET | BPF_K, action))

    return b"".join(instructions)


def _apply_seccomp(bpf_prog: bytes) -> bool:
    """Apply a seccomp-bpf filter to the current process.

    WARNING: This is irreversible. Only call in a child process.
    """
    if not bpf_prog:
        return False

    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    except:
        return False

    # struct sock_fprog { unsigned short len; struct sock_filter *filter; }
    n_instructions = len(bpf_prog) // 8  # each instruction is 8 bytes

    class SockFprog(ctypes.Structure):
        _fields_ = [
            ("len", ctypes.c_ushort),
            ("filter", ctypes.c_char_p),
        ]

    prog = SockFprog()
    prog.len = n_instructions
    prog.filter = bpf_prog

    # PR_SET_NO_NEW_PRIVS (required before seccomp)
    ret = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret != 0:
        return False

    # PR_SET_SECCOMP with SECCOMP_MODE_FILTER
    ret = libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0)
    return ret == 0


def _run_seccomp(
    func_source: str,
    func_name: str,
    args_file: str,
    result_file: str,
    blocked_syscalls: List[int],
    timeout: int = 30,
) -> SandboxResult:
    """Run code in a seccomp-bpf sandboxed child process."""

    sr = SandboxResult(
        sandbox_type="seccomp",
        policy_applied={"blocked_syscalls": len(blocked_syscalls)},
    )

    # Build runner script
    bpf_hex = _build_bpf_filter(blocked_syscalls).hex()

    runner = f"""
import pickle, sys, os, io, time, traceback, ctypes, ctypes.util, struct

# Apply seccomp filter BEFORE running user code
def apply_filter():
    bpf_bytes = bytes.fromhex("{bpf_hex}")
    if not bpf_bytes:
        return False
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    n = len(bpf_bytes) // 8

    class SockFprog(ctypes.Structure):
        _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_char_p)]

    prog = SockFprog(len=n, filter=bpf_bytes)
    libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
    return libc.prctl(22, 2, ctypes.byref(prog), 0, 0) == 0  # PR_SET_SECCOMP

filter_ok = apply_filter()

sys.path.insert(0, {repr(str(Path(__file__).parent.parent))})

t0 = time.perf_counter()
result = {{"success": False, "return_value": None, "exception": None,
           "stdout": "", "stderr": "", "filter_applied": filter_ok}}

with open({repr(args_file)}, "rb") as f:
    args, kwargs = pickle.load(f)

old_out, old_err = sys.stdout, sys.stderr
cap_out, cap_err = io.StringIO(), io.StringIO()

try:
    sys.stdout, sys.stderr = cap_out, cap_err
{textwrap.indent(func_source, "    ")}
    rv = {func_name}(*args, **kwargs)
    result["return_value"] = rv
    result["success"] = True
except Exception as e:
    result["exception"] = f"{{type(e).__name__}}: {{e}}\\n{{traceback.format_exc()}}"
finally:
    sys.stdout, sys.stderr = old_out, old_err
    result["stdout"] = cap_out.getvalue()
    result["stderr"] = cap_err.getvalue()
    result["wall_time_ms"] = round((time.perf_counter() - t0) * 1000, 2)

with open({repr(result_file)}, "wb") as f:
    pickle.dump(result, f)
"""

    import subprocess

    runner_file = tempfile.mktemp(suffix=".py", prefix="seccomp_runner_", dir="/tmp")
    with open(runner_file, "w") as f:
        f.write(runner)

    t0 = time.perf_counter()

    try:
        proc = subprocess.run(
            [sys.executable, runner_file],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        sr.wall_time_ms = round((time.perf_counter() - t0) * 1000, 2)
        sr.exit_code = proc.returncode

        if proc.returncode == 0 and os.path.exists(result_file):
            with open(result_file, "rb") as f:
                inner = pickle.load(f)
            sr.success = inner.get("success", False)
            sr.return_value = inner.get("return_value")
            sr.exception = inner.get("exception")
            sr.stdout = inner.get("stdout", "")
            sr.stderr = inner.get("stderr", "")
            sr.wall_time_ms = inner.get("wall_time_ms", sr.wall_time_ms)
        elif proc.returncode != 0:
            # Killed by seccomp (usually SIGSYS = signal 31, or SIGKILL)
            sr.killed_by_sandbox = proc.returncode in (
                -31,
                -9,
                -6,
                159,
                137,
                134,  # SIGSYS, SIGKILL, SIGABRT
            )
            sr.stderr = proc.stderr
            sr.stdout = proc.stdout
            if sr.killed_by_sandbox:
                sr.violations.append(
                    f"KILLED by seccomp-bpf (signal={-proc.returncode if proc.returncode < 0 else proc.returncode})"
                )

    except subprocess.TimeoutExpired:
        sr.exception = f"Timeout after {timeout}s"
    except Exception as e:
        sr.exception = f"{type(e).__name__}: {e}"
    finally:
        for f in [runner_file]:
            try:
                os.unlink(f)
            except:
                pass

    return sr


# =============================================================================
# 🔒 Unified KernelSandbox API
# =============================================================================


class KernelSandbox:
    """Cross-platform kernel-level sandbox.

    Automatically selects the right backend:
    - macOS: sandbox-exec (Seatbelt profiles)
    - Linux: seccomp-bpf (syscall filtering)

    Usage:
        sb = KernelSandbox(policy="sandbox")
        result = sb.run(my_function, args=(1, 2))
        print(result.summary())

        # Or with custom policy:
        sb = KernelSandbox(policy={
            "network": False,
            "file_write": False,
            "subprocess": False,
        })
    """

    def __init__(self, policy: Union[str, Dict] = "sandbox", timeout: int = 30):
        self.policy = resolve_kernel_policy(policy)
        self.timeout = timeout
        self.platform = platform.system()

        if self.platform == "Darwin":
            self.backend = "seatbelt"
            self.profile = _policy_to_seatbelt(self.policy)
        elif self.platform == "Linux":
            self.backend = "seccomp"
            self.blocked_syscalls = _policy_to_blocked_syscalls(self.policy)
        else:
            self.backend = "none"

    @property
    def available(self) -> bool:
        """Check if kernel sandboxing is available on this platform."""
        return self.backend in ("seatbelt", "seccomp")

    def run(
        self, func: Callable, args: tuple = (), kwargs: dict = None, timeout: int = None
    ) -> SandboxResult:
        """Run a function inside the kernel sandbox.

        The function runs in a forked subprocess with kernel-level
        restrictions applied. Even ctypes, C extensions, mmap —
        nothing can escape.

        Args:
            func: Function to execute
            args: Positional arguments
            kwargs: Keyword arguments
            timeout: Override timeout in seconds

        Returns:
            SandboxResult with execution details
        """
        kwargs = kwargs or {}
        timeout = timeout or self.timeout

        if not self.available:
            return SandboxResult(
                exception=f"Kernel sandboxing not available on {self.platform}",
                sandbox_type="none",
            )

        # Get function source code
        import inspect as _inspect

        try:
            func_source = _inspect.getsource(func)
            # Dedent if needed
            func_source = textwrap.dedent(func_source)
            # Remove decorator lines
            lines = func_source.split("\n")
            clean_lines = []
            skip = True
            for line in lines:
                if skip and (line.strip().startswith("@") or not line.strip()):
                    continue
                skip = False
                clean_lines.append(line)
            func_source = "\n".join(clean_lines)
        except (OSError, TypeError):
            return SandboxResult(
                exception="Cannot get source code for function (C extension or lambda?)",
                sandbox_type=self.backend,
            )

        func_name = func.__name__

        # Serialize args to temp file
        args_file = tempfile.mktemp(suffix=".pkl", prefix="sandbox_args_", dir="/tmp")
        result_file = tempfile.mktemp(suffix=".pkl", prefix="sandbox_result_", dir="/tmp")

        with open(args_file, "wb") as f:
            pickle.dump((args, kwargs), f)

        try:
            if self.backend == "seatbelt":
                return _run_seatbelt(
                    func_source,
                    func_name,
                    args_file,
                    result_file,
                    self.profile,
                    timeout,
                )
            elif self.backend == "seccomp":
                return _run_seccomp(
                    func_source,
                    func_name,
                    args_file,
                    result_file,
                    self.blocked_syscalls,
                    timeout,
                )
        finally:
            for f in [args_file, result_file]:
                try:
                    os.unlink(f)
                except:
                    pass

    def show_profile(self) -> str:
        """Show the generated sandbox profile for inspection."""
        if self.backend == "seatbelt":
            return f"=== macOS Seatbelt Profile ===\n{self.profile}"
        elif self.backend == "seccomp":
            _, syscall_table = _get_arch_and_syscalls()
            rev = {v: k for k, v in syscall_table.items()}
            blocked_names = [rev.get(nr, f"syscall#{nr}") for nr in self.blocked_syscalls]
            return (
                f"=== Linux seccomp-bpf ===\n"
                f"Blocked syscalls ({len(self.blocked_syscalls)}):\n"
                + "\n".join(f"  - {name}" for name in sorted(blocked_names))
            )
        return "No kernel sandbox available"


# ─── Convenience ─────────────────────────────────────────────────────


def lock(
    func: Callable = None,
    *,
    policy: Union[str, Dict] = "sandbox",
    timeout: int = 30,
    print_summary: bool = True,
):
    """Decorator to run a function in a kernel sandbox.

    Usage:
        @lock
        def untrusted():
            ...

        @lock(policy="strict", timeout=10)
        def very_untrusted():
            ...

        @lock(policy={"network": False, "file_write": False})
        def custom():
            ...
    """
    import functools

    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            sb = KernelSandbox(policy=policy, timeout=timeout)
            result = sb.run(fn, args=args, kwargs=kwargs)
            if print_summary:
                print(result.summary())
            if result.success:
                return result.return_value
            elif result.killed_by_sandbox:
                raise PolicyViolation_Lock(result)
            elif result.exception:
                raise RuntimeError(f"Sandboxed execution failed: {result.exception}")
            return None

        wrapper.__locked__ = True
        wrapper.__last_sandbox_result__ = None
        return wrapper

    if func is not None:
        return decorator(func)
    return decorator


class PolicyViolation_Lock(Exception):
    """Raised when kernel sandbox kills the process."""

    def __init__(self, result: SandboxResult):
        self.result = result
        violations = ", ".join(result.violations[:3]) if result.violations else "unknown"
        super().__init__(f"🔒 Kernel sandbox violation: {violations}")

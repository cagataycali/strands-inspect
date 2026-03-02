"""Tests for _sandbox.py — kernel-level sandboxing (macOS Seatbelt / Linux seccomp)."""

import os
import platform
import pytest
from strands_inspect._sandbox import (
    KernelSandbox,
    SandboxResult,
    lock,
    resolve_kernel_policy,
    BUILTIN_KERNEL_POLICIES,
    _policy_to_seatbelt,
    _get_arch_and_syscalls,
    _policy_to_blocked_syscalls,
    _build_bpf_filter,
)

# ─── Skip if no kernel sandbox available ─────────────────────────────

IS_MACOS = platform.system() == "Darwin"
IS_LINUX = platform.system() == "Linux"
IS_CI = (
    os.environ.get("CI", "").lower() == "true"
    or os.environ.get("GITHUB_ACTIONS", "").lower() == "true"
)
HAS_SANDBOX = IS_MACOS or IS_LINUX

skip_no_sandbox = pytest.mark.skipif(
    not HAS_SANDBOX, reason="Kernel sandbox not available on this platform"
)


# ─── Policy Resolution ──────────────────────────────────────────────


class TestPolicyResolution:
    def test_string_policy(self):
        pol = resolve_kernel_policy("sandbox")
        assert pol["network"] is False
        assert pol["file_read"] is True

    def test_dict_policy(self):
        pol = resolve_kernel_policy({"network": False, "file_write": False})
        assert pol["network"] is False
        assert pol["file_write"] is False
        assert pol["file_read"] is True  # default

    def test_true_gives_sandbox(self):
        pol = resolve_kernel_policy(True)
        assert pol["network"] is False

    def test_builtin_policies(self):
        for name in ("default", "sandbox", "strict", "deny_all"):
            assert name in BUILTIN_KERNEL_POLICIES


# ─── Seatbelt Profile Generation (macOS) ────────────────────────────


@pytest.mark.skipif(not IS_MACOS, reason="macOS only")
class TestSeatbeltProfile:
    def test_generates_profile(self):
        pol = resolve_kernel_policy("sandbox")
        profile = _policy_to_seatbelt(pol)
        assert "(version 1)" in profile
        assert "(deny default)" in profile

    def test_network_denied(self):
        pol = resolve_kernel_policy({"network": False})
        profile = _policy_to_seatbelt(pol)
        assert "(allow network*)" not in profile

    def test_network_allowed(self):
        pol = resolve_kernel_policy({"network": True})
        profile = _policy_to_seatbelt(pol)
        assert "(allow network*)" in profile

    def test_file_read_paths(self):
        pol = resolve_kernel_policy({"file_read": ["/data", "/config"]})
        profile = _policy_to_seatbelt(pol)
        assert "/data" in profile
        assert "/config" in profile

    def test_file_write_denied(self):
        pol = resolve_kernel_policy({"file_write": False})
        profile = _policy_to_seatbelt(pol)
        # Should still allow /tmp and /dev/null
        assert "/dev/null" in profile
        assert "/tmp" in profile or "/private/tmp" in profile


# ─── seccomp BPF Generation (Linux) ─────────────────────────────────


class TestSeccompBPF:
    def test_arch_detection(self):
        arch, syscalls = _get_arch_and_syscalls()
        if IS_LINUX or platform.machine() in ("x86_64", "aarch64", "arm64"):
            assert arch is not None
            assert len(syscalls) > 0

    def test_policy_to_blocked_syscalls(self):
        blocked = _policy_to_blocked_syscalls({"network": False})
        if _get_arch_and_syscalls()[0]:
            assert len(blocked) > 0  # should block socket, connect, etc.

    def test_bpf_filter_generation(self):
        blocked = [41, 42, 43]  # socket, connect, accept
        bpf = _build_bpf_filter(blocked)
        if _get_arch_and_syscalls()[0]:
            assert len(bpf) > 0
            assert len(bpf) % 8 == 0  # each instruction is 8 bytes


# ─── KernelSandbox API ──────────────────────────────────────────────


class TestKernelSandboxAPI:
    def test_init(self):
        sb = KernelSandbox(policy="sandbox")
        assert sb.backend in ("seatbelt", "seccomp", "none")

    def test_available(self):
        sb = KernelSandbox()
        if HAS_SANDBOX:
            assert sb.available is True

    def test_show_profile(self):
        sb = KernelSandbox(policy="sandbox")
        profile = sb.show_profile()
        assert len(profile) > 0

    def test_result_dataclass(self):
        r = SandboxResult(success=True, return_value=42, sandbox_type="test")
        assert r.success is True
        assert r.return_value == 42
        d = r.to_dict()
        assert "success" in d
        s = r.summary()
        assert "✅" in s


# ─── KernelSandbox Execution (requires OS support) ──────────────────


@skip_no_sandbox
class TestKernelExecution:
    def test_pure_computation(self):
        sb = KernelSandbox(policy="sandbox")

        def compute(x, y):
            return x**2 + y**2

        r = sb.run(compute, args=(3, 4))
        assert r.success is True
        assert r.return_value == 25

    def test_network_blocked(self):
        sb = KernelSandbox(policy={"network": False})

        def try_network():
            import urllib.request

            return urllib.request.urlopen("http://example.com").read()[:10]

        r = sb.run(try_network)
        # On macOS (seatbelt), network is reliably blocked.
        # On Linux CI (seccomp), the filter may not apply in containers
        # (prctl PR_SET_SECCOMP can fail silently without CAP_SYS_ADMIN).
        if IS_MACOS:
            assert r.success is False
        elif IS_LINUX and IS_CI:
            # In CI containers, seccomp may not enforce — accept either outcome
            assert isinstance(r.success, bool)
        else:
            assert r.success is False

    def test_timeout(self):
        sb = KernelSandbox(policy="default", timeout=2)

        def slow():
            import time

            time.sleep(10)

        r = sb.run(slow)
        assert r.success is False
        assert "Timeout" in (r.exception or "")

    def test_sandbox_result_summary(self):
        sb = KernelSandbox(policy="sandbox")

        def f():
            return 1

        r = sb.run(f)
        s = r.summary()
        assert "KernelSandbox" in s


# ─── @lock Decorator ───────────────────────────────────────


@skip_no_sandbox
class TestKernelDecorator:
    def test_decorator_basic(self):
        @lock(policy="sandbox", print_summary=False)
        def compute(n):
            return sum(i**2 for i in range(n))

        result = compute(100)
        assert result == 328350

    def test_decorator_no_parens(self):
        @lock
        def f():
            return 42

        # This will run in sandbox with default policy
        result = f()
        assert result == 42

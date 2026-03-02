"""Tests for _decorator.py — @inspect decorator, policies, syscall hooks."""

import os
import tempfile
import pytest
from strands_inspect._decorator import (
    watch,
    replay,
    list_sessions,
    InspectSession,
    PolicyViolation,
    BUILTIN_POLICIES,
    ALL_CATEGORIES,
    _match_path,
    _match_host,
    _match_package,
    _resolve_decision,
    SyscallHooks,
)

# ─── Policy Constants ────────────────────────────────────────────────


class TestPolicyConstants:
    def test_all_categories_count(self):
        assert len(ALL_CATEGORIES) == 20

    def test_builtin_policies_exist(self):
        for name in ("allow_all", "deny_all", "deny_network", "deny_write", "sandbox", "strict"):
            assert name in BUILTIN_POLICIES

    def test_deny_all_blocks_everything(self):
        pol = BUILTIN_POLICIES["deny_all"]
        for cat in ALL_CATEGORIES:
            assert pol[cat] == "deny"

    def test_allow_all_logs_everything(self):
        pol = BUILTIN_POLICIES["allow_all"]
        for cat in ALL_CATEGORIES:
            assert pol[cat] == "log"

    def test_sandbox_allows_reads(self):
        pol = BUILTIN_POLICIES["sandbox"]
        assert pol["file.read"] == "log"
        assert pol["import"] == "log"

    def test_sandbox_denies_dangerous(self):
        pol = BUILTIN_POLICIES["sandbox"]
        for cat in (
            "file.write",
            "file.delete",
            "network",
            "subprocess",
            "os.system",
            "os.exec",
            "meta.ctypes",
            "meta.code",
        ):
            assert pol[cat] == "deny", f"{cat} should be deny in sandbox"


# ─── Granular Matching ───────────────────────────────────────────────


class TestPathMatching:
    def test_match_exact(self):
        assert _match_path("/tmp/foo.txt", ["/tmp/**"])

    def test_match_glob(self):
        assert _match_path("/tmp/sub/deep/file.txt", ["/tmp/**"])

    def test_no_match(self):
        assert not _match_path("/etc/passwd", ["/tmp/**"])

    def test_basename_match(self):
        assert _match_path("/some/path/file.txt", ["*.txt"])


class TestHostMatching:
    def test_exact_match(self):
        assert _match_host("connect → api.openai.com:443", ["api.openai.com"])

    def test_wildcard_match(self):
        assert _match_host("connect → bedrock.us-east-1.amazonaws.com:443", ["*.amazonaws.com"])

    def test_no_match(self):
        assert not _match_host("connect → evil.com:443", ["api.openai.com"])

    def test_case_insensitive(self):
        assert _match_host("connect → API.OpenAI.COM:443", ["api.openai.com"])


class TestPackageMatching:
    def test_exact(self):
        assert _match_package("json", ["json", "math"])

    def test_subpackage(self):
        assert _match_package("json.decoder", ["json"])

    def test_no_match(self):
        assert not _match_package("os", ["json", "math"])

    def test_glob(self):
        assert _match_package("my_pkg", ["my_*"])


class TestResolveDecision:
    def test_string_policy(self):
        assert _resolve_decision("deny", "file.read", "/etc/hosts") == "deny"
        assert _resolve_decision("allow", "file.read", "/etc/hosts") == "allow"
        assert _resolve_decision("log", "file.read", "/etc/hosts") == "log"

    def test_callable_policy(self):
        fn = lambda a, d: "allow" if "/tmp" in d else "deny"
        assert _resolve_decision(fn, "file.read", "/tmp/f.txt") == "allow"
        assert _resolve_decision(fn, "file.read", "/etc/hosts") == "deny"

    def test_dict_policy_paths(self):
        pol = {"action": "allow", "paths": ["/tmp/**"]}
        assert _resolve_decision(pol, "file.read", "/tmp/foo.txt") == "allow"
        assert _resolve_decision(pol, "file.read", "/etc/hosts") == "deny"

    def test_dict_policy_hosts(self):
        pol = {"action": "allow", "hosts": ["*.openai.com"]}
        assert _resolve_decision(pol, "network", "connect → api.openai.com:443") == "allow"
        assert _resolve_decision(pol, "network", "connect → evil.com:443") == "deny"

    def test_dict_policy_packages(self):
        pol = {"action": "allow", "packages": ["json", "math"]}
        assert _resolve_decision(pol, "import", "json") == "allow"
        assert _resolve_decision(pol, "import", "os") == "deny"

    def test_none_defaults_to_log(self):
        assert _resolve_decision(None, "file.read", "x") == "log"

    def test_callable_error_fails_closed(self):
        fn = lambda a, d: 1 / 0  # raises
        assert _resolve_decision(fn, "x", "y") == "deny"


# ─── @inspect Decorator — Basic ─────────────────────────────────────


class TestInspectBasic:
    def test_simple_function(self):
        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def add(a, b):
            return a + b

        assert add(2, 3) == 5

    def test_session_captured(self):
        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def mul(a, b):
            return a * b

        mul(3, 4)
        s = mul.__last_session__
        assert isinstance(s, InspectSession)
        assert s.return_value == 12
        assert s.exception is None

    def test_exception_captured(self):
        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def bad():
            raise ValueError("boom")

        bad()
        s = bad.__last_session__
        assert s.exception is not None
        assert "boom" in s.exception

    def test_stdout_captured(self):
        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def loud():
            print("hello stdout")
            return 42

        loud()
        assert "hello stdout" in loud.__last_session__.stdout

    def test_inspected_flag(self):
        @watch(dump=False, profile=False, print_summary=False)
        def f():
            pass

        assert f.__inspected__ is True


# ─── @inspect — Policy Enforcement ──────────────────────────────────


class TestInspectPolicies:
    def test_deny_all_blocks_open(self):
        @watch(policy="deny_all", dump=False, profile=False, print_summary=False)
        def read_file():
            return open("/etc/hosts").read()

        read_file()
        s = read_file.__last_session__
        assert len(s.denied) >= 1
        assert s.exception is not None

    def test_deny_network(self):
        @watch(policy="deny_network", dump=False, profile=False, print_summary=False)
        def try_net():
            import socket

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("example.com", 80))

        try_net()
        s = try_net.__last_session__
        assert len(s.denied) >= 1

    def test_path_based_allow(self, tmp_file):
        @watch(
            policy={"file.read": {"action": "allow", "paths": ["/tmp/**"]}, "import": "log"},
            dump=False,
            profile=False,
            print_summary=False,
        )
        def read_tmp():
            with open(tmp_file) as f:
                return f.read()

        result = read_tmp()
        assert result == "hello world"
        assert read_tmp.__last_session__.exception is None

    def test_path_based_deny(self):
        @watch(
            policy={"file.read": {"action": "allow", "paths": ["/tmp/**"]}, "import": "log"},
            dump=False,
            profile=False,
            print_summary=False,
        )
        def read_etc():
            return open("/etc/hosts").read()

        read_etc()
        assert len(read_etc.__last_session__.denied) >= 1

    def test_callable_policy(self):
        @watch(
            policy={"file.read": lambda a, d: "allow" if "/tmp" in d else "deny", "import": "log"},
            dump=False,
            profile=False,
            print_summary=False,
        )
        def read_blocked():
            return open("/etc/hosts").read()

        read_blocked()
        assert len(read_blocked.__last_session__.denied) >= 1

    def test_global_callable_policy(self):
        @watch(
            policy=lambda a, d: "log" if a in ("file.read", "import") else "deny",
            dump=False,
            profile=False,
            print_summary=False,
        )
        def try_system():
            os.system("echo hi")

        try_system()
        assert len(try_system.__last_session__.denied) >= 1


# ─── @inspect — New Hooks ────────────────────────────────────────────


class TestNewHooks:
    def test_os_system_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_system():
            os.system("echo pwned")

        try_system()
        blocked = [d["action"] for d in try_system.__last_session__.denied]
        assert "os.system" in blocked

    def test_os_remove_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_rm():
            try:
                os.remove("/tmp/nonexistent_file_xyz")
            except PolicyViolation:
                pass

        try_rm()
        blocked = [d["action"] for d in try_rm.__last_session__.denied]
        assert "file.delete" in blocked

    def test_os_link_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_link():
            try:
                os.link("/tmp/a", "/tmp/b")
            except PolicyViolation:
                pass

        try_link()
        blocked = [d["action"] for d in try_link.__last_session__.denied]
        assert "file.link" in blocked

    def test_os_mkdir_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_mkdir():
            try:
                os.mkdir("/tmp/sandbox_test_dir_xyz")
            except PolicyViolation:
                pass

        try_mkdir()
        blocked = [d["action"] for d in try_mkdir.__last_session__.denied]
        assert "file.mkdir" in blocked

    def test_os_chmod_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_chmod():
            try:
                os.chmod("/tmp", 0o777)
            except PolicyViolation:
                pass

        try_chmod()
        blocked = [d["action"] for d in try_chmod.__last_session__.denied]
        assert "file.chmod" in blocked

    def test_os_rename_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_rename():
            try:
                os.rename("/tmp/a_xyz", "/tmp/b_xyz")
            except PolicyViolation:
                pass

        try_rename()
        blocked = [d["action"] for d in try_rename.__last_session__.denied]
        assert "file.move" in blocked

    def test_os_kill_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_kill():
            try:
                os.kill(99999, 0)
            except PolicyViolation:
                pass

        try_kill()
        blocked = [d["action"] for d in try_kill.__last_session__.denied]
        assert "process.kill" in blocked

    def test_meta_code_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_eval():
            eval("1+1")

        try_eval()
        blocked = [d["action"] for d in try_eval.__last_session__.denied]
        assert "meta.code" in blocked

    def test_meta_ctypes_blocked(self):
        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_ctypes():
            import ctypes

            ctypes.CDLL("libc.dylib")

        try_ctypes()
        blocked = [d["action"] for d in try_ctypes.__last_session__.denied]
        assert "meta.ctypes" in blocked


# ─── @inspect — Dump & Replay ───────────────────────────────────────


class TestDumpReplay:
    def test_dump_creates_file(self, tmp_dir):
        @watch(policy="allow_all", dump=True, dump_dir=tmp_dir, profile=False, print_summary=False)
        def my_fn():
            return 42

        my_fn()
        dump_path = my_fn.__last_dump__
        assert dump_path is not None
        assert os.path.exists(dump_path)

    def test_replay_loads_session(self, tmp_dir):
        @watch(policy="allow_all", dump=True, dump_dir=tmp_dir, profile=False, print_summary=False)
        def my_fn():
            return 99

        my_fn()
        s = replay(my_fn.__last_dump__)
        assert isinstance(s, InspectSession)
        assert s.return_value == 99
        assert s.func_name == "my_fn"

    def test_session_summary(self):
        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def f():
            return 1

        f()
        summary = f.__last_session__.summary()
        assert "InspectSession" in summary

    def test_session_diff(self):
        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def f(x):
            return x

        f(1)
        s1 = f.__last_session__
        f(2)
        s2 = f.__last_session__
        d = s1.diff(s2)
        assert "return_changed" in d


# ─── Hook Install/Uninstall ─────────────────────────────────────────


class TestHookLifecycle:
    def test_hooks_restore_after_decorator(self):
        import builtins

        original_open = builtins.open

        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def f():
            return 1

        f()

        # Hooks should be uninstalled
        assert builtins.open is original_open

    def test_hooks_restore_on_exception(self):
        import builtins

        original_open = builtins.open

        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def f():
            raise RuntimeError("boom")

        f()

        assert builtins.open is original_open

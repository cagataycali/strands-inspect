"""Tests to close remaining coverage gaps across all modules."""

import os
import sys
import json
import tempfile
import platform
import pytest

# ─── _tool.py gaps ──────────────────────────────────────────────────


class TestToolGaps:
    """Cover uncovered branches in _tool.py"""

    def test_scan_with_depth(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="scan", target="json", depth=1)
        assert r["status"] == "success"

    def test_call_registered_function(self):
        from strands_inspect._tool import inspect_tool, _FUNCTION_REGISTRY

        _FUNCTION_REGISTRY["test_fn"] = lambda x: x * 2
        r = inspect_tool(action="call", target="test_fn", args="[5]")
        assert r["status"] == "success"
        assert "10" in r["content"][0]["text"]

    def test_call_with_bad_args(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="call", target="json.dumps", args="not json")
        assert r["status"] == "error"

    def test_inspect_registered_function(self):
        from strands_inspect._tool import inspect_tool, _FUNCTION_REGISTRY, _FUNCTION_SOURCE

        _FUNCTION_REGISTRY["my_inspect_fn"] = lambda: 42
        _FUNCTION_SOURCE["my_inspect_fn"] = "lambda: 42"
        r = inspect_tool(action="inspect", target="my_inspect_fn")
        assert r["status"] == "success"

    def test_source_registered_function(self):
        from strands_inspect._tool import inspect_tool, _FUNCTION_SOURCE

        _FUNCTION_SOURCE["src_fn"] = "def src_fn(): return 1"
        r = inspect_tool(action="source", target="src_fn")
        assert r["status"] == "success"

    def test_create_syntax_error(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="create", code="def broken(")
        assert r["status"] == "error"

    def test_create_no_code(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="create")
        assert r["status"] == "error"

    def test_generate_missing(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="generate", target="totally.missing.xyz")
        assert r["status"] == "error"

    def test_generate_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="generate")
        assert r["status"] == "error"

    def test_search_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="search")
        assert r["status"] == "error"

    def test_source_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="source")
        assert r["status"] == "error"

    def test_inspect_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="inspect")
        assert r["status"] == "error"

    def test_call_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="call")
        assert r["status"] == "error"

    def test_profile_action(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="profile", code="1+1")
        assert r["status"] == "success"

    def test_profile_no_code(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="profile")
        assert r["status"] == "error"

    def test_graph_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="graph")
        assert r["status"] == "error"

    def test_connections_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="connections")
        assert r["status"] == "error"

    def test_connections_no_dot(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="connections", target="nodot")
        assert r["status"] == "error"

    def test_hotspots_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="hotspots")
        assert r["status"] == "error"

    def test_unused_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="unused")
        assert r["status"] == "error"

    def test_deps_no_target(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="deps")
        assert r["status"] == "error"

    def test_install_no_package(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="install")
        assert r["status"] == "error"

    def test_exec_multiline(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="exec", code="x = 1\ny = 2\nx + y")
        assert r["status"] == "success"
        assert "3" in r["content"][0]["text"]

    def test_describe_callable_class(self):
        from strands_inspect._tool import _describe_callable

        info = _describe_callable(dict, "dict")
        assert info["type"] == "class"

    def test_format_scan_many_classes(self):
        from strands_inspect._tool import inspect_tool

        r = inspect_tool(action="scan", target="collections")
        assert r["status"] == "success"

    def test_serialize_result_types(self):
        from strands_inspect._tool import _serialize_result

        assert _serialize_result(None) == "None"
        assert _serialize_result(42) == "42"
        assert _serialize_result("hi") == "'hi'"
        assert "bytes" in _serialize_result(b"data")
        assert _serialize_result([1, 2]) == "[\n  1,\n  2\n]"


# ─── _decorator.py gaps ──────────────────────────────────────────────


class TestDecoratorGaps:
    def test_with_profiling(self):
        from strands_inspect._decorator import watch

        @watch(policy="allow_all", dump=False, profile=True, print_summary=False)
        def compute():
            return sum(range(1000))

        r = compute()
        assert r == 499500
        s = compute.__last_session__
        assert s.memory_peak_kb >= 0

    def test_print_summary(self, capsys):
        from strands_inspect._decorator import watch

        @watch(policy="allow_all", dump=False, profile=False, print_summary=True)
        def f():
            return 1

        f()
        captured = capsys.readouterr()
        assert "InspectSession" in captured.out

    def test_session_attach_to_complex_return(self):
        from strands_inspect._decorator import watch

        class Container:
            pass

        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def f():
            c = Container()
            c.value = 42
            return c

        r = f()
        assert hasattr(r, "__inspect_session__")

    def test_list_sessions(self, tmp_dir):
        from strands_inspect._decorator import watch, list_sessions

        @watch(policy="allow_all", dump=True, dump_dir=tmp_dir, profile=False, print_summary=False)
        def f():
            return 1

        f()
        sessions = list_sessions(tmp_dir)
        assert len(sessions) >= 1
        assert "path" in sessions[0]

    def test_re_run(self, tmp_dir):
        from strands_inspect._decorator import watch

        @watch(policy="allow_all", dump=False, profile=False, print_summary=False)
        def add(a, b):
            return a + b

        add(1, 2)
        s = add.__last_session__
        # re_run with same args
        result = s.re_run()
        assert result == 3
        # re_run with new args
        result = s.re_run(10, 20)
        assert result == 30

    def test_re_run_no_func(self):
        from strands_inspect._decorator import InspectSession

        s = InspectSession("test", "test")
        with pytest.raises(RuntimeError):
            s.re_run()

    def test_deny_write_policy(self):
        from strands_inspect._decorator import watch

        @watch(policy="deny_write", dump=False, profile=False, print_summary=False)
        def try_write():
            with open("/tmp/test_deny_write_xyz.txt", "w") as f:
                f.write("blocked")

        try_write()
        s = try_write.__last_session__
        assert len(s.denied) >= 1

    def test_subprocess_check_call_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation
        import subprocess

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_check_call():
            try:
                subprocess.check_call(["echo", "hi"])
            except PolicyViolation:
                pass

        try_check_call()
        blocked = [d["action"] for d in try_check_call.__last_session__.denied]
        assert "subprocess" in blocked

    def test_os_popen_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_popen():
            try:
                os.popen("echo hi")
            except PolicyViolation:
                pass

        try_popen()
        blocked = [d["action"] for d in try_popen.__last_session__.denied]
        assert "os.system" in blocked

    def test_shutil_rmtree_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation
        import shutil

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_rmtree():
            try:
                shutil.rmtree("/tmp/nonexistent_xyz_123")
            except PolicyViolation:
                pass

        try_rmtree()
        blocked = [d["action"] for d in try_rmtree.__last_session__.denied]
        assert "file.delete" in blocked

    def test_shutil_copy_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation
        import shutil

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_copy():
            try:
                shutil.copy("/tmp/a", "/tmp/b")
            except PolicyViolation:
                pass

        try_copy()
        blocked = [d["action"] for d in try_copy.__last_session__.denied]
        assert "file.write" in blocked

    def test_os_symlink_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_symlink():
            try:
                os.symlink("/tmp/a", "/tmp/b_sym")
            except PolicyViolation:
                pass

        try_symlink()
        blocked = [d["action"] for d in try_symlink.__last_session__.denied]
        assert "file.link" in blocked

    def test_os_makedirs_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_makedirs():
            try:
                os.makedirs("/tmp/sandbox_deep/nested/dir")
            except PolicyViolation:
                pass

        try_makedirs()
        blocked = [d["action"] for d in try_makedirs.__last_session__.denied]
        assert "file.mkdir" in blocked

    def test_os_fd_io_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_fd():
            fd = os.open("/dev/null", os.O_RDONLY)
            try:
                os.read(fd, 10)
            except PolicyViolation:
                pass
            finally:
                os.close(fd)

        try_fd()
        blocked = [d["action"] for d in try_fd.__last_session__.denied]
        assert "file.fd_io" in blocked

    @pytest.mark.skipif(not hasattr(os, "fork"), reason="No fork on this platform")
    def test_os_fork_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation

        @watch(policy="sandbox", dump=False, profile=False, print_summary=False)
        def try_fork():
            try:
                os.fork()
            except PolicyViolation:
                pass

        try_fork()
        blocked = [d["action"] for d in try_fork.__last_session__.denied]
        assert "process.fork" in blocked

    def test_importlib_import_module_blocked(self):
        from strands_inspect._decorator import watch, PolicyViolation
        import sys

        # Remove from cache so import hook fires
        mods_to_remove = [k for k in sys.modules if k.startswith("_not_real_pkg")]

        @watch(
            policy={"import": {"action": "allow", "packages": ["json"]}, "file.read": "log"},
            dump=False,
            profile=False,
            print_summary=False,
        )
        def try_import():
            import importlib

            try:
                importlib.import_module("_not_real_pkg_xyz")
            except (PolicyViolation, ModuleNotFoundError):
                pass

        try_import()
        assert len(try_import.__last_session__.denied) >= 1


# ─── _graph.py gaps ─────────────────────────────────────────────────


class TestGraphGaps:
    def test_connections_class(self):
        from strands_inspect._graph import build_package_graph, find_connections

        g = build_package_graph("json")
        conn = find_connections(g["files"], "JSONEncoder")
        assert "target" in conn

    def test_graph_action_missing_package(self):
        from strands_inspect._graph import handle_graph_action

        r = handle_graph_action("totally_fake_pkg_xyz")
        assert r["status"] == "error"

    def test_connections_action_missing(self):
        from strands_inspect._graph import handle_connections_action

        r = handle_connections_action("fake_xyz.func")
        assert r["status"] == "error"


# ─── _profile.py gaps ───────────────────────────────────────────────


class TestProfileGaps:
    def test_profile_with_sort_by_tottime(self):
        from strands_inspect._profile import profile_code

        r = profile_code("sum(range(100))", sort_by="tottime")
        assert r["wall_time_ms"] >= 0

    def test_profile_with_sort_by_calls(self):
        from strands_inspect._profile import profile_code

        r = profile_code("sum(range(100))", sort_by="calls")
        assert r["wall_time_ms"] >= 0

    def test_export_default_path(self):
        from strands_inspect._profile import profile_code, export_json

        r = profile_code("1+1")
        path = export_json(r)
        assert os.path.exists(path)
        os.unlink(path)

    def test_profile_complex_code(self):
        from strands_inspect._profile import profile_code

        code = """
def compute():
    total = 0
    for i in range(1000):
        total += i * i
    return total
result = compute()
"""
        r = profile_code(code)
        assert r["wall_time_ms"] >= 0

    def test_get_viewer_path(self):
        from strands_inspect._profile import get_viewer_path

        p = get_viewer_path()
        assert "index.html" in p


# ─── _sandbox.py gaps ───────────────────────────────────────────────


class TestSandboxGaps:
    def test_sandbox_result_to_dict(self):
        from strands_inspect._sandbox import SandboxResult

        r = SandboxResult(success=True, return_value=[1, 2, 3])
        d = r.to_dict()
        assert d["success"] is True

    def test_sandbox_result_summary_killed(self):
        from strands_inspect._sandbox import SandboxResult

        r = SandboxResult(killed_by_sandbox=True, exit_code=-9, violations=["test"])
        s = r.summary()
        assert "KILLED" in s

    def test_sandbox_result_summary_exception(self):
        from strands_inspect._sandbox import SandboxResult

        r = SandboxResult(exception="test error")
        s = r.summary()
        assert "test error" in s

    def test_resolve_deny_all(self):
        from strands_inspect._sandbox import resolve_kernel_policy

        p = resolve_kernel_policy("deny_all")
        assert p["network"] is False
        assert p["file_read"] is False

    def test_lock_unavailable_platform(self):
        from strands_inspect._sandbox import KernelSandbox

        sb = KernelSandbox.__new__(KernelSandbox)
        sb.backend = "none"
        sb.policy = {}
        sb.timeout = 5
        sb.platform = "Windows"
        r = sb.run(lambda: 1)
        assert r.success is False

    def test_show_profile_no_backend(self):
        from strands_inspect._sandbox import KernelSandbox

        sb = KernelSandbox.__new__(KernelSandbox)
        sb.backend = "none"
        assert "No kernel sandbox" in sb.show_profile()

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_seatbelt_strict_profile(self):
        from strands_inspect._sandbox import _policy_to_seatbelt, resolve_kernel_policy

        p = resolve_kernel_policy("strict")
        profile = _policy_to_seatbelt(p)
        assert "(deny default)" in profile
        assert "/dev/null" in profile

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_seatbelt_ipc_denied(self):
        from strands_inspect._sandbox import _policy_to_seatbelt

        profile = _policy_to_seatbelt(
            {
                "ipc": False,
                "file_read": True,
                "file_write": True,
                "network": True,
                "subprocess": True,
                "sysctl": True,
                "mmap_exec": True,
            }
        )
        assert "ipc-posix-shm" in profile

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_seatbelt_network_hosts(self):
        from strands_inspect._sandbox import _policy_to_seatbelt

        profile = _policy_to_seatbelt(
            {
                "network": ["1.2.3.4"],
                "file_read": True,
                "file_write": True,
                "subprocess": True,
                "sysctl": True,
                "ipc": True,
                "mmap_exec": True,
            }
        )
        assert "1.2.3.4" in profile

    @pytest.mark.skipif(platform.system() != "Darwin", reason="macOS only")
    def test_seatbelt_file_write_paths(self):
        from strands_inspect._sandbox import _policy_to_seatbelt

        profile = _policy_to_seatbelt(
            {
                "file_write": ["/data"],
                "file_read": True,
                "network": True,
                "subprocess": True,
                "sysctl": True,
                "ipc": True,
                "mmap_exec": True,
            }
        )
        assert "/data" in profile

    def test_policy_violation_kernel(self):
        from strands_inspect._sandbox import PolicyViolation_Lock, SandboxResult

        r = SandboxResult(violations=["network blocked"])
        e = PolicyViolation_Lock(r)
        assert "network blocked" in str(e)

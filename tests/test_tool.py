"""Tests for _tool.py — the 16-action Strands agent tool."""

import json
import pytest
from strands_inspect._tool import (
    inspect_tool,
    _resolve_dotted_path,
    _deep_scan_package,
    _safe_call,
    _safe_exec_code,
    _PACKAGE_CACHE,
    _FUNCTION_REGISTRY,
)

# ─── Package Scanner ────────────────────────────────────────────────


class TestScan:
    def test_scan_json(self):
        r = inspect_tool(action="scan", target="json")
        assert r["status"] == "success"
        assert "json" in r["content"][0]["text"].lower()

    def test_scan_pathlib(self):
        r = inspect_tool(action="scan", target="pathlib")
        assert r["status"] == "success"
        assert "Path" in r["content"][0]["text"]

    def test_scan_missing_package(self):
        r = inspect_tool(action="scan", target="nonexistent_package_xyz_123")
        assert r["status"] == "error"

    def test_scan_no_target(self):
        r = inspect_tool(action="scan")
        assert r["status"] == "error"

    def test_scan_caches_result(self):
        _PACKAGE_CACHE.clear()
        inspect_tool(action="scan", target="json")
        assert any("json" in k for k in _PACKAGE_CACHE)


# ─── Inspect ────────────────────────────────────────────────────────


class TestInspect:
    def test_inspect_function(self):
        r = inspect_tool(action="inspect", target="json.dumps")
        assert r["status"] == "success"
        text = r["content"][0]["text"]
        assert "dumps" in text

    def test_inspect_class(self):
        r = inspect_tool(action="inspect", target="pathlib.Path")
        assert r["status"] == "success"
        assert "Path" in r["content"][0]["text"]

    def test_inspect_module(self):
        r = inspect_tool(action="inspect", target="json")
        assert r["status"] == "success"
        assert "Module" in r["content"][0]["text"]

    def test_inspect_missing(self):
        r = inspect_tool(action="inspect", target="nonexistent.thing")
        assert r["status"] == "error"


# ─── Call ────────────────────────────────────────────────────────────


class TestCall:
    def test_call_json_dumps(self):
        r = inspect_tool(
            action="call", target="json.dumps", args='[{"a": 1}]', kwargs='{"indent": 2}'
        )
        assert r["status"] == "success"
        assert '"a"' in r["content"][0]["text"]

    def test_call_os_getcwd(self):
        r = inspect_tool(action="call", target="os.getcwd")
        assert r["status"] == "success"

    def test_call_missing_target(self):
        r = inspect_tool(action="call")
        assert r["status"] == "error"

    def test_call_non_callable(self):
        r = inspect_tool(action="call", target="os.sep")
        assert r["status"] == "error"


# ─── Search ──────────────────────────────────────────────────────────


class TestSearch:
    def test_search_json(self):
        r = inspect_tool(action="search", target="json", query="dumps")
        assert r["status"] == "success"
        assert "dumps" in r["content"][0]["text"]

    def test_search_no_results(self):
        r = inspect_tool(action="search", target="json", query="xyznonexistent")
        assert r["status"] == "success"
        assert "No matches" in r["content"][0]["text"]

    def test_search_missing_query(self):
        r = inspect_tool(action="search", target="json")
        assert r["status"] == "error"


# ─── Generate ───────────────────────────────────────────────────────


class TestGenerate:
    def test_generate_function(self):
        r = inspect_tool(action="generate", target="json.dumps")
        assert r["status"] == "success"
        assert "import" in r["content"][0]["text"]

    def test_generate_class(self):
        r = inspect_tool(action="generate", target="pathlib.Path")
        assert r["status"] == "success"


# ─── Exec ────────────────────────────────────────────────────────────


class TestExec:
    def test_exec_simple(self):
        r = inspect_tool(action="exec", code="1 + 1")
        assert r["status"] == "success"
        assert "2" in r["content"][0]["text"]

    def test_exec_with_print(self):
        r = inspect_tool(action="exec", code="print('hello')")
        assert r["status"] == "success"
        assert "hello" in r["content"][0]["text"]

    def test_exec_error(self):
        r = inspect_tool(action="exec", code="1/0")
        assert r["status"] == "success"
        assert "ZeroDivision" in r["content"][0]["text"]

    def test_exec_no_code(self):
        r = inspect_tool(action="exec")
        assert r["status"] == "error"


# ─── Create ──────────────────────────────────────────────────────────


class TestCreate:
    def test_create_function(self):
        _FUNCTION_REGISTRY.clear()
        r = inspect_tool(action="create", code="def add(a, b): return a + b")
        assert r["status"] == "success"
        assert "add" in _FUNCTION_REGISTRY

    def test_create_and_call(self):
        inspect_tool(action="create", code="def mul(a, b): return a * b")
        r = inspect_tool(action="call", target="mul", args="[3, 4]")
        assert r["status"] == "success"
        assert "12" in r["content"][0]["text"]

    def test_create_bare_expression(self):
        r = inspect_tool(action="create", code="x = 42\nx", name="get_x")
        assert r["status"] == "success"


# ─── Source ──────────────────────────────────────────────────────────


class TestSource:
    def test_source_function(self):
        r = inspect_tool(action="source", target="json.tool.main")
        # May or may not have source depending on Python build
        assert r["status"] in ("success", "error")

    def test_source_builtin(self):
        r = inspect_tool(action="source", target="len")
        assert r["status"] == "error"  # C builtin, no source


# ─── List ────────────────────────────────────────────────────────────


class TestList:
    def test_list_empty(self):
        _PACKAGE_CACHE.clear()
        _FUNCTION_REGISTRY.clear()
        r = inspect_tool(action="list")
        assert r["status"] == "success"

    def test_list_after_scan(self):
        inspect_tool(action="scan", target="json")
        r = inspect_tool(action="list")
        assert r["status"] == "success"
        assert "json" in r["content"][0]["text"].lower()


# ─── Unknown action ─────────────────────────────────────────────────


class TestUnknown:
    def test_unknown_action(self):
        r = inspect_tool(action="totally_fake")
        assert r["status"] == "error"


# ─── Internal helpers ────────────────────────────────────────────────


class TestHelpers:
    def test_resolve_dotted_path(self):
        obj = _resolve_dotted_path("json.dumps")
        assert callable(obj)

    def test_resolve_missing(self):
        obj = _resolve_dotted_path("nonexistent.module.thing")
        assert obj is None

    def test_safe_call(self):
        r = _safe_call("json.dumps", [{"a": 1}])
        assert r["return_value"] == '{"a": 1}'

    def test_safe_exec(self):
        r = _safe_exec_code("x = 2 + 3\nx")
        assert r["return_value"] == 5

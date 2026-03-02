"""Tests for _profile.py — runtime profiler."""

import pytest
from strands_inspect._profile import (
    profile_code,
    format_profile_report,
    export_json,
    render_timeline,
    render_flamegraph,
    handle_profile_action,
)


class TestProfileCode:
    def test_basic_profile(self):
        r = profile_code("x = sum(range(1000))\nx")
        assert r["wall_time_ms"] > 0
        assert r["return_value"] == 499500

    def test_memory_tracking(self):
        r = profile_code("data = [i**2 for i in range(10000)]")
        assert r["memory"]["peak_kb"] > 0
        assert r["memory"]["current_kb"] >= 0

    def test_cpu_profiling(self):
        r = profile_code("import json; json.dumps({'a': 1})")
        assert r["cpu"]["total_calls"] >= 0
        assert isinstance(r["cpu"]["top_functions"], list)

    def test_timeline(self):
        r = profile_code("data = list(range(100000))", timeline=True)
        assert len(r["timeline"]) > 0
        assert "time_ms" in r["timeline"][0]
        assert "current_kb" in r["timeline"][0]

    def test_gc_stats(self):
        r = profile_code("x = [[] for _ in range(100)]")
        assert "objects_before" in r["gc"]
        assert "objects_after" in r["gc"]

    def test_resource_stats(self):
        r = profile_code("1+1")
        assert "max_rss_mb" in r["resource"]
        assert "user_time_ms" in r["resource"]

    def test_captures_stdout(self):
        r = profile_code("print('hello profile')")
        assert "hello profile" in r["stdout"]

    def test_captures_exception(self):
        r = profile_code("1/0")
        assert r["exception"] is not None
        assert "ZeroDivision" in r["exception"]

    def test_return_value_of_last_expr(self):
        r = profile_code("x = 10\nx * 2")
        assert r["return_value"] == 20

    def test_no_timeline(self):
        r = profile_code("1+1", timeline=False)
        assert r["timeline"] == []


class TestRenderers:
    def test_render_timeline(self):
        samples = [
            {"time_ms": 0, "current_kb": 100, "peak_kb": 100},
            {"time_ms": 50, "current_kb": 200, "peak_kb": 200},
            {"time_ms": 100, "current_kb": 150, "peak_kb": 200},
        ]
        text = render_timeline(samples)
        assert "Memory Timeline" in text
        assert "Peak" in text

    def test_render_timeline_empty(self):
        text = render_timeline([])
        assert "no timeline" in text

    def test_render_flamegraph(self):
        funcs = [
            {"name": "func_a", "cumtime_ms": 100, "calls": 5},
            {"name": "func_b", "cumtime_ms": 50, "calls": 10},
        ]
        text = render_flamegraph(funcs)
        assert "func_a" in text
        assert "func_b" in text

    def test_render_flamegraph_empty(self):
        text = render_flamegraph([])
        assert "no CPU data" in text


class TestFormatReport:
    def test_format_report(self):
        r = profile_code("x = sum(range(1000))")
        text = format_profile_report(r)
        assert "Runtime Profile" in text
        assert "Wall time" in text
        assert "Peak memory" in text


class TestExportJson:
    def test_export(self, tmp_dir):
        import os

        r = profile_code("1+1")
        path = os.path.join(tmp_dir, "test_profile.json")
        out = export_json(r, path)
        assert os.path.exists(out)

        import json

        with open(out) as f:
            data = json.load(f)
        assert "wall_time_ms" in data
        assert "cpu" in data
        assert "memory" in data


class TestToolHandler:
    def test_handle_profile(self):
        r = handle_profile_action(code="sum(range(100))")
        assert r["status"] == "success"
        assert "Runtime Profile" in r["content"][0]["text"]

    def test_handle_profile_no_code(self):
        r = handle_profile_action(code="")
        assert r["status"] == "error"

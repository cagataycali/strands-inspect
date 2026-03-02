"""Tests for _graph.py — AST call graph engine."""

import pytest
from strands_inspect._graph import (
    analyze_file,
    find_package_source,
    build_package_graph,
    build_call_graph,
    find_most_called,
    find_unused_functions,
    find_connections,
    build_dependency_graph,
    find_duplicates,
    find_complexity_hotspots,
    compute_metrics,
    handle_graph_action,
    handle_connections_action,
    handle_hotspots_action,
    handle_unused_action,
    handle_deps_action,
)


class TestAnalyzeFile:
    def test_analyze_self(self):
        import strands_inspect._graph as mod

        result = analyze_file(mod.__file__)
        assert result is not None
        assert result["lines"] > 0
        assert len(result["functions"]) > 0
        assert len(result["classes"]) > 0

    def test_analyze_nonexistent(self):
        result = analyze_file("/nonexistent/file.py")
        assert result is None

    def test_analyze_syntax_error(self, tmp_dir):
        import os

        bad_file = os.path.join(tmp_dir, "bad.py")
        with open(bad_file, "w") as f:
            f.write("def broken(\n")
        result = analyze_file(bad_file)
        assert result is not None
        assert "error" in result


class TestPackageSource:
    def test_find_json(self):
        src = find_package_source("json")
        assert src is not None

    def test_find_missing(self):
        src = find_package_source("nonexistent_pkg_xyz")
        assert src is None


class TestBuildGraph:
    def test_build_json_graph(self):
        g = build_package_graph("json")
        assert g.get("package") == "json"
        assert "files" in g
        assert len(g["files"]) > 0

    def test_build_missing_package(self):
        g = build_package_graph("nonexistent_xyz")
        assert "error" in g


class TestAnalysisPasses:
    @pytest.fixture(autouse=True)
    def setup_graph(self):
        self.graph = build_package_graph("json")
        self.files = self.graph["files"]

    def test_call_graph(self):
        cg = build_call_graph(self.files)
        assert "calls_out" in cg
        assert "calls_in" in cg
        assert "all_defined" in cg

    def test_most_called(self):
        hot = find_most_called(self.files)
        assert isinstance(hot, list)
        if hot:
            assert "name" in hot[0]
            assert "call_count" in hot[0]

    def test_unused_functions(self):
        unused = find_unused_functions(self.files)
        assert isinstance(unused, list)

    def test_connections(self):
        conn = find_connections(self.files, "dumps")
        assert "target" in conn
        assert "called_by" in conn
        assert "calls" in conn

    def test_dependency_graph(self):
        deps = build_dependency_graph(self.files)
        assert "graph" in deps
        assert "total_edges" in deps

    def test_duplicates(self):
        dupes = find_duplicates(self.files)
        assert isinstance(dupes, list)

    def test_complexity_hotspots(self):
        hot = find_complexity_hotspots(self.files)
        assert isinstance(hot, list)

    def test_metrics(self):
        m = compute_metrics(self.files)
        assert m["total_files"] > 0
        assert m["total_lines"] > 0


class TestToolHandlers:
    def test_handle_graph(self):
        r = handle_graph_action("json")
        assert r["status"] == "success"

    def test_handle_graph_with_query(self):
        r = handle_graph_action("json", query="dumps")
        assert r["status"] == "success"

    def test_handle_hotspots(self):
        r = handle_hotspots_action("json")
        assert r["status"] == "success"

    def test_handle_unused(self):
        r = handle_unused_action("json")
        assert r["status"] == "success"

    def test_handle_deps(self):
        r = handle_deps_action("json")
        assert r["status"] == "success"

    def test_handle_connections(self):
        r = handle_connections_action("json.dumps")
        assert r["status"] == "success"

    def test_handle_missing_package(self):
        r = handle_graph_action("nonexistent_xyz")
        assert r["status"] == "error"

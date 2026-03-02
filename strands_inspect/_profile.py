"""
🏥 Runtime Profiler — like clinic.js but for Python.

Wraps code execution with:
- Memory tracking (tracemalloc) — per-line allocation, peak, leaks
- CPU profiling (cProfile) — call counts, cumulative time, flamegraph
- Resource usage (resource module) — RSS, page faults
- GC stats — object counts, collection generations
- Timeline — memory snapshots over time during execution

All Python stdlib. Zero dependencies.
"""

import ast
import cProfile
import gc
import io
import linecache
import os
import pstats
import resource
import sys
import textwrap
import time
import tracemalloc
import traceback
import threading
from typing import Any, Dict, List, Optional

# ─── Memory Snapshot Timeline ────────────────────────────────────────


class MemoryTimeline:
    """Background thread that takes memory snapshots at intervals."""

    def __init__(self, interval_ms: int = 50):
        self.interval = interval_ms / 1000.0
        self.snapshots: List[Dict] = []
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2)

    def _sample_loop(self):
        t0 = time.monotonic()
        while self._running:
            current, peak = tracemalloc.get_traced_memory()
            elapsed = time.monotonic() - t0
            self.snapshots.append(
                {
                    "time_ms": round(elapsed * 1000, 1),
                    "current_kb": round(current / 1024, 1),
                    "peak_kb": round(peak / 1024, 1),
                }
            )
            time.sleep(self.interval)


# ─── Core Profiler ───────────────────────────────────────────────────


def profile_code(
    code: str,
    top_n: int = 20,
    sort_by: str = "cumulative",
    trace_memory: bool = True,
    timeline: bool = True,
    timeline_interval_ms: int = 50,
) -> Dict[str, Any]:
    """Profile Python code execution — memory, CPU, allocations, timeline.

    Args:
        code: Python code to profile
        top_n: Number of top functions to show in CPU profile
        sort_by: Sort CPU profile by (cumulative, tottime, calls, memory)
        trace_memory: Enable tracemalloc memory tracking
        timeline: Enable memory timeline sampling
        timeline_interval_ms: Timeline sample interval in ms

    Returns:
        Dict with all profiling data
    """
    result = {
        "cpu": {},
        "memory": {},
        "timeline": [],
        "gc": {},
        "resource": {},
        "stdout": "",
        "stderr": "",
        "return_value": None,
        "exception": None,
        "wall_time_ms": 0,
    }

    ns = {"__builtins__": __builtins__}

    # ── Pre-execution state ──────────────────────────────────────
    gc.collect()
    gc_stats_before = {
        "objects": len(gc.get_objects()),
        "garbage": len(gc.garbage),
        "collections": [gc.get_stats()[i]["collections"] for i in range(3)],
    }
    resource_before = resource.getrusage(resource.RUSAGE_SELF)

    # ── Start memory tracking ────────────────────────────────────
    was_tracing = tracemalloc.is_tracing()
    if trace_memory:
        if was_tracing:
            tracemalloc.stop()
        tracemalloc.start(25)  # 25 frames deep for accurate stacks

    # ── Start timeline sampler ───────────────────────────────────
    mem_timeline = None
    if timeline and trace_memory:
        mem_timeline = MemoryTimeline(interval_ms=timeline_interval_ms)
        mem_timeline.start()

    # ── Start CPU profiler ───────────────────────────────────────
    profiler = cProfile.Profile()

    # ── Capture stdout/stderr ────────────────────────────────────
    old_stdout, old_stderr = sys.stdout, sys.stderr
    captured_out, captured_err = io.StringIO(), io.StringIO()

    # ── Execute ──────────────────────────────────────────────────
    wall_start = time.perf_counter()

    try:
        sys.stdout, sys.stderr = captured_out, captured_err

        # Parse AST to capture return value of last expression
        tree = ast.parse(code)
        last_expr = None

        if tree.body and isinstance(tree.body[-1], ast.Expr):
            last_expr = tree.body.pop()

        # Profile the execution
        compiled_main = compile(ast.Module(body=tree.body, type_ignores=[]), "<profile>", "exec")

        profiler.enable()

        if tree.body:
            exec(compiled_main, ns)

        if last_expr:
            compiled_expr = compile(ast.Expression(body=last_expr.value), "<profile>", "eval")
            result["return_value"] = eval(compiled_expr, ns)

        profiler.disable()

    except Exception as e:
        profiler.disable()
        result["exception"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"

    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
        result["stdout"] = captured_out.getvalue()
        result["stderr"] = captured_err.getvalue()

    wall_end = time.perf_counter()
    result["wall_time_ms"] = round((wall_end - wall_start) * 1000, 2)

    # ── Stop timeline sampler ────────────────────────────────────
    if mem_timeline:
        mem_timeline.stop()
        result["timeline"] = mem_timeline.snapshots

    # ── Collect memory stats ─────────────────────────────────────
    if trace_memory:
        snapshot = tracemalloc.take_snapshot()
        current_mem, peak_mem = tracemalloc.get_traced_memory()

        # Top allocations by line
        top_stats = snapshot.statistics("lineno")
        top_allocs = []
        for stat in top_stats[:top_n]:
            frame = stat.traceback[0]
            top_allocs.append(
                {
                    "file": frame.filename,
                    "line": frame.lineno,
                    "size_kb": round(stat.size / 1024, 2),
                    "count": stat.count,
                    "source": _get_source_line(frame.filename, frame.lineno),
                }
            )

        # Top allocations by file
        file_stats = snapshot.statistics("filename")
        top_files = []
        for stat in file_stats[:15]:
            top_files.append(
                {
                    "file": stat.traceback[0].filename,
                    "size_kb": round(stat.size / 1024, 2),
                    "count": stat.count,
                }
            )

        result["memory"] = {
            "current_kb": round(current_mem / 1024, 2),
            "peak_kb": round(peak_mem / 1024, 2),
            "top_allocations": top_allocs,
            "top_files": top_files,
        }

        if not was_tracing:
            tracemalloc.stop()

    # ── Collect CPU stats ────────────────────────────────────────
    stream = io.StringIO()
    stats = pstats.Stats(profiler, stream=stream)

    # Sort key mapping
    sort_keys = {
        "cumulative": "cumulative",
        "cumtime": "cumulative",
        "tottime": "tottime",
        "time": "tottime",
        "calls": "calls",
        "ncalls": "calls",
        "name": "name",
    }
    sort_key = sort_keys.get(sort_by, "cumulative")

    stats.sort_stats(sort_key)
    stats.print_stats(top_n)
    cpu_text = stream.getvalue()

    # Extract structured data via pstats
    cpu_functions = []
    total_calls = 0
    if hasattr(stats, "stats"):
        for func_key, func_stats in stats.stats.items():
            filename, lineno, name = func_key
            cc, nc, tt, ct, callers = func_stats
            total_calls += nc
            if name == "<module>" and filename == "<profile>":
                continue
            if "disable" in name:
                continue
            short_file = _shorten_path(filename) if filename != "~" else name
            cpu_functions.append(
                {
                    "name": name,
                    "file": short_file,
                    "line": lineno,
                    "calls": nc,
                    "tottime_ms": round(tt * 1000, 3),
                    "cumtime_ms": round(ct * 1000, 3),
                    "per_call_ms": round((ct / nc) * 1000, 3) if nc > 0 else 0,
                }
            )

    cpu_functions.sort(key=lambda x: -x["cumtime_ms"])

    result["cpu"] = {
        "total_calls": total_calls,
        "top_functions": cpu_functions[:top_n],
        "raw_text": cpu_text,
    }

    gc.collect()
    gc_stats_after = {
        "objects": len(gc.get_objects()),
        "garbage": len(gc.garbage),
        "collections": [gc.get_stats()[i]["collections"] for i in range(3)],
    }

    result["gc"] = {
        "objects_before": gc_stats_before["objects"],
        "objects_after": gc_stats_after["objects"],
        "objects_delta": gc_stats_after["objects"] - gc_stats_before["objects"],
        "garbage": gc_stats_after["garbage"],
        "gen0_collections": gc_stats_after["collections"][0] - gc_stats_before["collections"][0],
        "gen1_collections": gc_stats_after["collections"][1] - gc_stats_before["collections"][1],
        "gen2_collections": gc_stats_after["collections"][2] - gc_stats_before["collections"][2],
    }

    # ── Resource usage ───────────────────────────────────────────
    resource_after = resource.getrusage(resource.RUSAGE_SELF)
    result["resource"] = {
        "max_rss_mb": (
            round(resource_after.ru_maxrss / (1024 * 1024), 2)
            if sys.platform == "linux"
            else round(resource_after.ru_maxrss / (1024 * 1024), 2)
        ),
        "user_time_ms": round((resource_after.ru_utime - resource_before.ru_utime) * 1000, 2),
        "system_time_ms": round((resource_after.ru_stime - resource_before.ru_stime) * 1000, 2),
        "page_faults": resource_after.ru_majflt - resource_before.ru_majflt,
        "voluntary_ctx_switches": resource_after.ru_nvcsw - resource_before.ru_nvcsw,
        "involuntary_ctx_switches": resource_after.ru_nivcsw - resource_before.ru_nivcsw,
    }

    return result


# ─── Helpers ─────────────────────────────────────────────────────────


def _get_source_line(filename: str, lineno: int) -> str:
    """Get a source line for annotation."""
    try:
        line = linecache.getline(filename, lineno).strip()
        return line[:120] if line else ""
    except:
        return ""


def _shorten_path(path: str) -> str:
    """Shorten file paths for readability."""
    if not path:
        return "?"
    # Show just the last 2 parts
    parts = path.replace("\\", "/").split("/")
    if len(parts) > 2:
        return "/".join(parts[-2:])
    return path


# ─── ASCII Timeline Chart ───────────────────────────────────────────


def render_timeline(snapshots: List[Dict], width: int = 60) -> str:
    """Render an ASCII memory timeline chart (like clinic.js)."""
    if not snapshots:
        return "(no timeline data)"

    max_kb = max(s["current_kb"] for s in snapshots) or 1
    max_time = snapshots[-1]["time_ms"] if snapshots else 1

    lines = []
    lines.append(f"Memory Timeline ({len(snapshots)} samples, {max_time:.0f}ms)")
    lines.append(f"Peak: {max_kb:.1f} KB")
    lines.append("")

    # Downsample to fit width
    step = max(1, len(snapshots) // width)
    sampled = snapshots[::step][:width]

    # Render bars
    height = 12
    for row in range(height, 0, -1):
        threshold = (row / height) * max_kb
        line_chars = []
        for s in sampled:
            if s["current_kb"] >= threshold:
                # Color based on percentage of peak
                pct = s["current_kb"] / max_kb
                if pct > 0.8:
                    line_chars.append("█")
                elif pct > 0.5:
                    line_chars.append("▓")
                elif pct > 0.2:
                    line_chars.append("▒")
                else:
                    line_chars.append("░")
            else:
                line_chars.append(" ")

        # Y-axis label
        if row == height:
            label = f"{max_kb:>7.1f}KB │"
        elif row == height // 2:
            label = f"{max_kb/2:>7.1f}KB │"
        elif row == 1:
            label = f"{'0':>7}KB │"
        else:
            label = f"{'':>8} │"

        lines.append(f"{label}{''.join(line_chars)}│")

    # X-axis
    lines.append(f"{'':>8} └{'─' * len(sampled)}┘")
    lines.append(f"{'':>9}0ms{' ' * (len(sampled) - 6)}{max_time:.0f}ms")

    return "\n".join(lines)


# ─── Flamegraph-style Output ────────────────────────────────────────


def render_flamegraph(cpu_functions: List[Dict], width: int = 70) -> str:
    """Render a text-based flamegraph-like view of CPU time."""
    if not cpu_functions:
        return "(no CPU data)"

    max_time = cpu_functions[0]["cumtime_ms"] if cpu_functions else 1
    if max_time == 0:
        max_time = 1

    lines = []
    lines.append("CPU Flamegraph (cumulative time)")
    lines.append("─" * width)

    for f in cpu_functions[:25]:
        name = f["name"]
        cumtime = f["cumtime_ms"]
        calls = f["calls"]
        pct = (cumtime / max_time) * 100 if max_time > 0 else 0

        bar_len = max(1, int((cumtime / max_time) * (width - 35)))
        bar = "█" * bar_len

        # Color indicator
        if pct > 50:
            indicator = "🔴"
        elif pct > 20:
            indicator = "🟡"
        else:
            indicator = "🟢"

        line = f"  {indicator} {name:<25} {cumtime:>8.2f}ms  {calls:>5}× │{bar}"
        lines.append(line)

    lines.append("─" * width)
    return "\n".join(lines)


# ─── Format Full Report ─────────────────────────────────────────────


def format_profile_report(result: Dict) -> str:
    """Format the complete profile report like clinic.js."""
    sections = []

    sections.append("# 🏥 Runtime Profile Report")
    sections.append("=" * 65)

    # ── Summary ──────────────────────────────────────────────────
    sections.append(f"\n⏱️  **Wall time**: {result['wall_time_ms']:.2f}ms")
    sections.append(f"💾 **Peak memory**: {result['memory'].get('peak_kb', 0):.1f} KB")
    sections.append(f"📞 **Total calls**: {result['cpu'].get('total_calls', 0):,}")

    res = result.get("resource", {})
    sections.append(
        f"🖥️  **User CPU**: {res.get('user_time_ms', 0):.2f}ms | **System**: {res.get('system_time_ms', 0):.2f}ms"
    )
    sections.append(
        f"📄 **Max RSS**: {res.get('max_rss_mb', 0):.1f} MB | **Page faults**: {res.get('page_faults', 0)}"
    )

    gc_info = result.get("gc", {})
    sections.append(
        f"♻️  **GC**: +{gc_info.get('objects_delta', 0)} objects | gen0: {gc_info.get('gen0_collections', 0)}, gen1: {gc_info.get('gen1_collections', 0)}, gen2: {gc_info.get('gen2_collections', 0)}"
    )

    # ── Output ───────────────────────────────────────────────────
    if result.get("stdout"):
        out = result["stdout"].rstrip()
        if len(out) > 500:
            out = out[:500] + "\n... [truncated]"
        sections.append(f"\n📤 **Output**:\n```\n{out}\n```")

    if result.get("return_value") is not None:
        rv = repr(result["return_value"])
        if len(rv) > 300:
            rv = rv[:300] + "..."
        sections.append(f"\n↩️  **Return**: `{rv}`")

    if result.get("exception"):
        sections.append(f"\n❌ **Exception**:\n```\n{result['exception']}\n```")

    # ── Memory Timeline ──────────────────────────────────────────
    if result.get("timeline"):
        sections.append(f"\n{'─' * 65}")
        sections.append("## 📈 Memory Timeline\n")
        sections.append(f"```\n{render_timeline(result['timeline'])}\n```")

    # ── CPU Flamegraph ───────────────────────────────────────────
    if result["cpu"].get("top_functions"):
        sections.append(f"\n{'─' * 65}")
        sections.append("## 🔥 CPU Profile\n")
        sections.append(f"```\n{render_flamegraph(result['cpu']['top_functions'])}\n```")

    # ── Top Memory Allocations ───────────────────────────────────
    if result["memory"].get("top_allocations"):
        sections.append(f"\n{'─' * 65}")
        sections.append("## 💾 Top Memory Allocations (by line)\n")
        for alloc in result["memory"]["top_allocations"][:15]:
            source = alloc["source"]
            if source:
                source = f"  `{source}`"
            sections.append(
                f"  {alloc['size_kb']:>8.1f} KB  ({alloc['count']:>4} allocs)  {_shorten_path(alloc['file'])}:{alloc['line']}{source}"
            )

    if result["memory"].get("top_files"):
        sections.append(f"\n## 📁 Memory by File\n")
        for f in result["memory"]["top_files"][:10]:
            sections.append(
                f"  {f['size_kb']:>8.1f} KB  ({f['count']:>5} allocs)  {_shorten_path(f['file'])}"
            )

    # ── Context Switches ─────────────────────────────────────────
    if res.get("voluntary_ctx_switches", 0) > 0 or res.get("involuntary_ctx_switches", 0) > 0:
        sections.append(f"\n## ⚡ Context Switches")
        sections.append(
            f"  Voluntary: {res.get('voluntary_ctx_switches', 0)} | Involuntary: {res.get('involuntary_ctx_switches', 0)}"
        )

    sections.append(f"\n{'=' * 65}")

    return "\n".join(sections)


def export_json(result: Dict, path: str = None) -> str:
    """Export profile result as JSON for the web viewer."""
    import json as _json

    if path is None:
        import tempfile

        path = os.path.join(tempfile.gettempdir(), "strands_inspect_profile.json")

    # Make result JSON-serializable
    clean = dict(result)
    if clean.get("return_value") is not None:
        try:
            _json.dumps(clean["return_value"])
        except (TypeError, ValueError):
            clean["return_value"] = repr(clean["return_value"])

    # Remove raw cProfile text (verbose)
    if "cpu" in clean and "raw_text" in clean["cpu"]:
        del clean["cpu"]["raw_text"]

    with open(path, "w") as f:
        _json.dump(clean, f, indent=2, default=str)

    return path


def get_viewer_path() -> str:
    """Get the path to the HTML viewer."""
    return os.path.join(os.path.dirname(__file__), "docs", "index.html")


# ─── Tool Action Handler ────────────────────────────────────────────


def handle_profile_action(
    code: str,
    top_n: int = 20,
    sort_by: str = "cumulative",
    timeline_interval_ms: int = 50,
) -> Dict[str, Any]:
    """Handle the 'profile' action from inspect_tool."""
    if not code:
        return {"status": "error", "content": [{"text": "code parameter required for profile"}]}

    try:
        result = profile_code(
            code=code,
            top_n=top_n,
            sort_by=sort_by,
            trace_memory=True,
            timeline=True,
            timeline_interval_ms=timeline_interval_ms,
        )

        # Export JSON for web viewer
        json_path = export_json(result)
        viewer_path = get_viewer_path()

        text = format_profile_report(result)
        text += f"\n\n📊 **Web Viewer**: `open {viewer_path}`"
        text += f"\n💾 **JSON dump**: `{json_path}`"
        text += (
            f"\n🔗 Drop the JSON into the viewer, or: `open {viewer_path} && pbcopy < {json_path}`"
        )

        return {"status": "success", "content": [{"text": text}]}
    except Exception as e:
        return {
            "status": "error",
            "content": [
                {"text": f"Profile error: {type(e).__name__}: {e}\n{traceback.format_exc()}"}
            ],
        }

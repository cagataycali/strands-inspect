"""
🕸️ Package Graph Engine — static analysis for any Python package.

Builds call graphs, finds connections, dead code, hotspots, and coupling.
Works on installed packages by finding their source files on disk.
"""

import ast
import os
import pkgutil
import importlib
from collections import defaultdict, Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ── AST Visitors ──────────────────────────────────────────────────────


class SymbolCollector(ast.NodeVisitor):
    """Walk one file's AST and collect every defined + referenced symbol."""

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.defined_functions: List[str] = []
        self.defined_classes: List[str] = []
        self.imports: List[Dict[str, str]] = []
        self.references: Set[str] = set()
        self.call_graph: List[Tuple[str, str]] = []  # (caller, callee) pairs
        self.string_refs: Set[str] = set()
        self.decorators: List[str] = []
        self.docstrings: Dict[str, str] = {}
        self.line_count = 0
        self.function_lines: Dict[str, int] = {}
        self._current_class: Optional[str] = None
        self._current_function: Optional[str] = None

    def _qualified_name(self, name: str) -> str:
        if self._current_class:
            return f"{self._current_class}.{name}"
        return name

    def visit_FunctionDef(self, node):
        name = self._qualified_name(node.name)
        self.defined_functions.append(name)
        self.function_lines[name] = (node.end_lineno or node.lineno) - node.lineno + 1

        # Docstring
        if (
            node.body
            and isinstance(node.body[0], ast.Expr)
            and isinstance(node.body[0].value, ast.Constant)
            and isinstance(node.body[0].value.value, str)
        ):
            self.docstrings[name] = node.body[0].value.value.strip().split("\n")[0][:120]

        # Decorators
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                self.decorators.append(dec.id)
                self.call_graph.append((name, dec.id))
            elif isinstance(dec, ast.Attribute):
                self.decorators.append(dec.attr)

        # Track current function for call graph
        old_func = self._current_function
        self._current_function = name
        self.generic_visit(node)
        self._current_function = old_func

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        self.defined_classes.append(node.name)
        old_class = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = old_class

    def visit_Call(self, node):
        """Track function calls for call graph."""
        callee = None
        if isinstance(node.func, ast.Name):
            callee = node.func.id
        elif isinstance(node.func, ast.Attribute):
            callee = node.func.attr

        if callee and self._current_function:
            self.call_graph.append((self._current_function, callee))
        elif callee:
            self.call_graph.append(("<module>", callee))

        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.append({"module": alias.name, "name": alias.asname or alias.name})
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        module = node.module or ""
        for alias in node.names:
            self.imports.append(
                {
                    "module": f"{module}.{alias.name}" if module else alias.name,
                    "name": alias.asname or alias.name,
                    "from_module": module,
                }
            )
        self.generic_visit(node)

    def visit_Name(self, node):
        self.references.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        self.references.add(node.attr)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str) and len(node.value) > 2:
            self.string_refs.add(node.value)
        self.generic_visit(node)


def analyze_file(filepath: str) -> Optional[Dict[str, Any]]:
    """Parse one Python file and return its symbol table + call graph."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except FileNotFoundError:
        return None
    try:
        pass  # dummy to keep structure
        tree = ast.parse(source, filename=filepath)
        c = SymbolCollector(filepath)
        c.line_count = source.count("\n") + 1
        c.visit(tree)
        return {
            "path": filepath,
            "lines": c.line_count,
            "functions": c.defined_functions,
            "classes": c.defined_classes,
            "imports": c.imports,
            "references": list(c.references),
            "call_graph": c.call_graph,
            "string_refs": list(c.string_refs),
            "decorators": c.decorators,
            "docstrings": c.docstrings,
            "function_lines": c.function_lines,
        }
    except SyntaxError as e:
        return {
            "path": filepath,
            "error": f"SyntaxError: {e}",
            "lines": 0,
            "functions": [],
            "classes": [],
            "imports": [],
            "references": [],
            "call_graph": [],
            "string_refs": [],
            "decorators": [],
            "docstrings": {},
            "function_lines": {},
        }


def find_package_source(package_name: str) -> Optional[str]:
    """Find the source directory of an installed package."""
    try:
        mod = importlib.import_module(package_name)
        if hasattr(mod, "__path__"):
            return mod.__path__[0]
        elif hasattr(mod, "__file__") and mod.__file__:
            return str(Path(mod.__file__).parent)
    except ImportError:
        pass
    return None


def build_package_graph(package_name: str) -> Dict[str, Any]:
    """Build complete graph from an installed package's source files."""
    source_dir = find_package_source(package_name)
    if not source_dir:
        return {"error": f"Cannot find source for '{package_name}'"}

    if not os.path.isdir(source_dir):
        return {"error": f"Source path is not a directory: {source_dir}"}

    files = {}
    for dirpath, _, filenames in os.walk(source_dir):
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, os.path.dirname(source_dir))
                result = analyze_file(full)
                if result:
                    result["relative"] = rel
                    files[rel] = result

    return {
        "package": package_name,
        "source_dir": source_dir,
        "files": files,
    }


# ── Analysis Passes ───────────────────────────────────────────────────


def build_call_graph(files: Dict) -> Dict[str, Any]:
    """Build global call graph across all files."""
    # caller → [callees]
    calls_out = defaultdict(set)
    # callee → [callers]
    calls_in = defaultdict(set)
    # All defined function names (bare)
    all_defined = {}  # bare_name → [(qualified_name, file)]

    for rel, info in files.items():
        for func in info.get("functions", []):
            bare = func.split(".")[-1]
            if bare not in all_defined:
                all_defined[bare] = []
            all_defined[bare].append({"qualified": func, "file": rel})

        for caller, callee in info.get("call_graph", []):
            # Qualify with file prefix for uniqueness
            file_prefix = rel.replace("/", ".").replace(".py", "")
            qualified_caller = f"{file_prefix}:{caller}"
            calls_out[qualified_caller].add(callee)
            calls_in[callee].add(qualified_caller)

    return {
        "calls_out": {k: sorted(v) for k, v in calls_out.items()},
        "calls_in": {k: sorted(v) for k, v in calls_in.items()},
        "all_defined": all_defined,
    }


def find_most_called(files: Dict, top_n: int = 30) -> List[Dict]:
    """Find the most called/referenced functions across the package."""
    # Count how many files reference each symbol
    ref_counter = Counter()
    call_counter = Counter()

    for rel, info in files.items():
        # Count references
        for ref in set(info.get("references", [])):
            ref_counter[ref] += 1

        # Count explicit calls
        for _, callee in info.get("call_graph", []):
            call_counter[callee] += 1

    # Map to defined functions
    all_defined_bare = set()
    for info in files.values():
        for func in info.get("functions", []):
            all_defined_bare.add(func.split(".")[-1])
        for cls in info.get("classes", []):
            all_defined_bare.add(cls)

    hotspots = []
    for name, call_count in call_counter.most_common(top_n * 2):
        ref_count = ref_counter.get(name, 0)
        is_internal = name in all_defined_bare

        hotspots.append(
            {
                "name": name,
                "call_count": call_count,
                "ref_count": ref_count,
                "total_score": call_count + ref_count,
                "is_internal": is_internal,
            }
        )

    hotspots.sort(key=lambda x: -x["total_score"])
    return hotspots[:top_n]


def find_unused_functions(files: Dict) -> List[Dict]:
    """Find functions defined but never referenced anywhere else."""
    all_refs: Set[str] = set()
    all_string_refs: Set[str] = set()
    all_callees: Set[str] = set()

    for info in files.values():
        all_refs.update(info.get("references", []))
        all_string_refs.update(info.get("string_refs", []))
        for _, callee in info.get("call_graph", []):
            all_callees.add(callee)

    combined_refs = all_refs | all_callees

    unused = []
    for rel, info in files.items():
        for func in info.get("functions", []):
            bare = func.split(".")[-1]
            if bare.startswith("_"):
                continue
            if bare in combined_refs:
                continue
            if any(bare in s for s in all_string_refs):
                continue
            unused.append(
                {
                    "function": func,
                    "file": rel,
                    "lines": info.get("function_lines", {}).get(func, 0),
                }
            )

    return sorted(unused, key=lambda x: -x["lines"])


def find_connections(files: Dict, target: str) -> Dict[str, Any]:
    """Find all connections to/from a specific function or class."""
    target_bare = target.split(".")[-1]

    callers = []  # who calls target
    callees = []  # what target calls
    co_references = []  # files that reference target

    for rel, info in files.items():
        # Check if target is referenced in this file
        if target_bare in info.get("references", []):
            co_references.append(rel)

        for caller, callee in info.get("call_graph", []):
            if callee == target_bare:
                callers.append({"caller": caller, "file": rel})
            if caller == target_bare or caller.endswith(f".{target_bare}"):
                callees.append({"callee": callee, "file": rel})

    # Find where target is defined
    defined_in = []
    for rel, info in files.items():
        for func in info.get("functions", []):
            if func == target or func.split(".")[-1] == target_bare:
                defined_in.append(
                    {
                        "qualified": func,
                        "file": rel,
                        "lines": info.get("function_lines", {}).get(func, 0),
                        "doc": info.get("docstrings", {}).get(func, ""),
                    }
                )
        for cls in info.get("classes", []):
            if cls == target_bare:
                defined_in.append({"qualified": cls, "file": rel, "type": "class"})

    return {
        "target": target,
        "defined_in": defined_in,
        "called_by": callers,
        "calls": callees,
        "referenced_in_files": co_references,
        "total_callers": len(callers),
        "total_callees": len(callees),
        "total_references": len(co_references),
    }


def build_dependency_graph(files: Dict) -> Dict[str, Any]:
    """Build file-level dependency graph."""
    # Map module paths to relative file paths
    module_to_file = {}
    for rel in files:
        mod_path = rel.replace("/", ".").replace(".py", "").replace(".__init__", "")
        module_to_file[mod_path] = rel

    graph = defaultdict(set)
    for rel, info in files.items():
        for imp in info.get("imports", []):
            mod = imp.get("from_module", imp.get("module", ""))
            for mod_path, target_file in module_to_file.items():
                if mod and (
                    mod.endswith(mod_path.split(".")[-1]) or mod_path.endswith(mod.split(".")[-1])
                ):
                    if target_file != rel:
                        graph[rel].add(target_file)

    # Compute coupling scores
    most_imported = Counter()
    for targets in graph.values():
        for t in targets:
            most_imported[t] += 1

    most_importing = Counter()
    for src, targets in graph.items():
        most_importing[src] = len(targets)

    return {
        "graph": {k: sorted(v) for k, v in graph.items()},
        "most_depended_on": most_imported.most_common(15),
        "most_dependencies": most_importing.most_common(15),
        "total_edges": sum(len(v) for v in graph.values()),
    }


def find_duplicates(files: Dict) -> List[Dict]:
    """Find same name defined in multiple files."""
    name_to_files = defaultdict(list)
    for rel, info in files.items():
        for func in info.get("functions", []):
            bare = func.split(".")[-1]
            if not bare.startswith("_"):
                name_to_files[bare].append({"file": rel, "qualified": func})
        for cls in info.get("classes", []):
            name_to_files[cls].append({"file": rel, "qualified": cls})

    return sorted(
        [
            {"name": n, "count": len(l), "locations": l}
            for n, l in name_to_files.items()
            if len(l) > 1
        ],
        key=lambda d: -d["count"],
    )


def find_complexity_hotspots(files: Dict) -> List[Dict]:
    """Find large files and functions that need attention."""
    hotspots = []

    for rel, info in files.items():
        lines = info.get("lines", 0)
        if lines > 300:
            hotspots.append(
                {
                    "type": "large_file",
                    "file": rel,
                    "lines": lines,
                    "functions": len(info.get("functions", [])),
                    "classes": len(info.get("classes", [])),
                }
            )

        for func, flines in info.get("function_lines", {}).items():
            if flines > 50:
                hotspots.append(
                    {
                        "type": "large_function",
                        "file": rel,
                        "function": func,
                        "lines": flines,
                    }
                )

    return sorted(hotspots, key=lambda x: -x.get("lines", 0))


def compute_metrics(files: Dict) -> Dict[str, Any]:
    """Compute summary metrics."""
    total_lines = sum(f.get("lines", 0) for f in files.values())
    total_functions = sum(len(f.get("functions", [])) for f in files.values())
    total_classes = sum(len(f.get("classes", [])) for f in files.values())
    total_calls = sum(len(f.get("call_graph", [])) for f in files.values())

    return {
        "total_files": len(files),
        "total_lines": total_lines,
        "total_functions": total_functions,
        "total_classes": total_classes,
        "total_call_edges": total_calls,
        "avg_lines_per_file": round(total_lines / max(len(files), 1), 1),
        "avg_functions_per_file": round(total_functions / max(len(files), 1), 1),
    }


# ── Formatters ────────────────────────────────────────────────────────


def format_graph_report(package_name: str, files: Dict) -> str:
    """Generate complete graph analysis report."""
    metrics = compute_metrics(files)
    hotfuncs = find_most_called(files)
    unused = find_unused_functions(files)
    dupes = find_duplicates(files)
    deps = build_dependency_graph(files)
    complexity = find_complexity_hotspots(files)

    total_dead = sum(u["lines"] for u in unused)

    sections = []
    sections.append(f"# 🕸️ {package_name} — Package Graph Analysis")
    sections.append("=" * 60)

    # Metrics
    sections.append(f"\n📊 **Metrics**")
    sections.append(
        f"  Files: {metrics['total_files']} | Lines: {metrics['total_lines']:,} | "
        f"Functions: {metrics['total_functions']} | Classes: {metrics['total_classes']} | "
        f"Call edges: {metrics['total_call_edges']}"
    )

    # Most called — THE key insight
    sections.append(f"\n🔥 **Most Called Functions** (hotspots)")
    for h in hotfuncs[:20]:
        tag = "📦" if h["is_internal"] else "📤"
        sections.append(
            f"  {tag} `{h['name']}` — called {h['call_count']}×, referenced {h['ref_count']}× (score: {h['total_score']})"
        )

    # Dependency graph — coupling
    sections.append(f"\n🔗 **Dependency Graph** ({deps['total_edges']} edges)")
    sections.append(f"  Most depended-on files:")
    for f, count in deps["most_depended_on"][:10]:
        sections.append(f"    {count}× ← `{f}`")
    sections.append(f"  Most importing files:")
    for f, count in deps["most_dependencies"][:10]:
        sections.append(f"    {count}→ `{f}`")

    # Unused / dead code
    sections.append(
        f"\n💀 **Potentially Dead Code** ({len(unused)} functions, ~{total_dead} lines)"
    )
    for u in unused[:15]:
        sections.append(f"  {u['lines']:>4} lines  `{u['function']}`  in {u['file']}")
    if len(unused) > 15:
        sections.append(f"  ... and {len(unused) - 15} more")

    # Duplicates
    if dupes:
        sections.append(f"\n🔄 **Duplicate Definitions** ({len(dupes)})")
        for d in dupes[:10]:
            locs = ", ".join(l["file"].split("/")[-1] for l in d["locations"])
            sections.append(f"  `{d['name']}` — {d['count']}× in: {locs}")

    # Complexity hotspots
    if complexity:
        sections.append(f"\n⚡ **Complexity Hotspots** ({len(complexity)})")
        for h in complexity[:10]:
            if h["type"] == "large_file":
                sections.append(
                    f"  📄 `{h['file']}` — {h['lines']} lines, {h['functions']} functions"
                )
            else:
                sections.append(f"  🔧 `{h['function']}` — {h['lines']} lines in {h['file']}")

    sections.append("\n" + "=" * 60)
    sections.append(
        "Use `action='connections', target='<function_name>'` to trace a specific function"
    )
    sections.append("Use `action='graph', target='<package>', query='<name>'` to search the graph")

    return "\n".join(sections)


def format_connections(conn: Dict) -> str:
    """Format connection analysis for a specific target."""
    parts = []
    target = conn["target"]

    parts.append(f"🕸️ **Connections for `{target}`**\n")

    if conn["defined_in"]:
        parts.append(f"📍 **Defined in:**")
        for d in conn["defined_in"]:
            line_info = f" ({d['lines']} lines)" if d.get("lines") else ""
            doc = f" — {d['doc']}" if d.get("doc") else ""
            parts.append(f"  `{d['qualified']}`{line_info} in `{d['file']}`{doc}")

    parts.append(f"\n⬆️ **Called by** ({conn['total_callers']} callers):")
    for c in conn["called_by"][:20]:
        parts.append(f"  ← `{c['caller']}` in `{c['file']}`")
    if conn["total_callers"] > 20:
        parts.append(f"  ... and {conn['total_callers'] - 20} more")

    parts.append(f"\n⬇️ **Calls** ({conn['total_callees']} callees):")
    seen = set()
    for c in conn["calls"][:20]:
        key = c["callee"]
        if key not in seen:
            parts.append(f"  → `{c['callee']}`")
            seen.add(key)

    parts.append(f"\n📁 **Referenced in** {conn['total_references']} file(s):")
    for f in conn["referenced_in_files"][:15]:
        parts.append(f"  `{f}`")

    return "\n".join(parts)


# ── Tool Action Handlers ──────────────────────────────────────────────


def handle_graph_action(target, query=None, depth=2):
    package_name = target.split(".")[0]
    pkg_graph = build_package_graph(package_name)
    if pkg_graph.get("error"):
        return {"status": "error", "content": [{"text": pkg_graph["error"]}]}
    files = pkg_graph["files"]
    if query:
        conn = find_connections(files, query)
        return {"status": "success", "content": [{"text": format_connections(conn)}]}
    return {"status": "success", "content": [{"text": format_graph_report(package_name, files)}]}


def handle_connections_action(target):
    parts = target.split(".")
    if len(parts) < 2:
        return {"status": "error", "content": [{"text": "Use format: package.function_name"}]}
    package_name = parts[0]
    func_name = ".".join(parts[1:])
    pkg_graph = build_package_graph(package_name)
    if pkg_graph.get("error"):
        return {"status": "error", "content": [{"text": pkg_graph["error"]}]}
    conn = find_connections(pkg_graph["files"], func_name)
    return {"status": "success", "content": [{"text": format_connections(conn)}]}


def handle_hotspots_action(target):
    package_name = target.split(".")[0]
    pkg_graph = build_package_graph(package_name)
    if pkg_graph.get("error"):
        return {"status": "error", "content": [{"text": pkg_graph["error"]}]}
    hotspots = find_most_called(pkg_graph["files"], top_n=30)
    lines = [f"🔥 Most Called Functions in `{package_name}`\n"]
    for h in hotspots:
        tag = "📦" if h["is_internal"] else "📤"
        lines.append(
            f"  {tag} `{h['name']}` — called {h['call_count']}×, ref {h['ref_count']}× (score: {h['total_score']})"
        )
    return {"status": "success", "content": [{"text": "\n".join(lines)}]}


def handle_unused_action(target):
    package_name = target.split(".")[0]
    pkg_graph = build_package_graph(package_name)
    if pkg_graph.get("error"):
        return {"status": "error", "content": [{"text": pkg_graph["error"]}]}
    unused = find_unused_functions(pkg_graph["files"])
    if not unused:
        return {
            "status": "success",
            "content": [{"text": f"✅ No obviously unused public functions in `{package_name}`."}],
        }
    total_dead = sum(u["lines"] for u in unused)
    lines = [f"💀 Dead Code in `{package_name}` ({len(unused)} functions, ~{total_dead} lines)\n"]
    for u in unused[:30]:
        lines.append(f"  {u['lines']:>4} lines  `{u['function']}`  in {u['file']}")
    if len(unused) > 30:
        lines.append(f"  ... and {len(unused) - 30} more")
    return {"status": "success", "content": [{"text": "\n".join(lines)}]}


def handle_deps_action(target):
    package_name = target.split(".")[0]
    pkg_graph = build_package_graph(package_name)
    if pkg_graph.get("error"):
        return {"status": "error", "content": [{"text": pkg_graph["error"]}]}
    deps = build_dependency_graph(pkg_graph["files"])
    lines = [f"🔗 Dependency Graph for `{package_name}` ({deps['total_edges']} edges)\n"]
    lines.append("Most depended-on:")
    for f, count in deps["most_depended_on"][:15]:
        lines.append(f"  {count}× ← `{f}`")
    lines.append("\nMost dependencies:")
    for f, count in deps["most_dependencies"][:15]:
        lines.append(f"  {count}→ `{f}`")
    if deps["graph"]:
        lines.append("\nFull graph:")
        for src, targets in sorted(deps["graph"].items()):
            lines.append(f"  `{src}`")
            for t in targets:
                lines.append(f"    → `{t}`")
    return {"status": "success", "content": [{"text": "\n".join(lines)}]}

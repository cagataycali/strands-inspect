"""
🔍 strands-inspect: Turn any Python package into a Strands tool.

The universal package scanner. Give it ANY pip package and it:
1. Deep-scans all modules, classes, functions, methods with full signatures
2. Builds a complete API map
3. Lets you call any function by dotted path
4. Auto-generates working code examples
5. Searches across the entire API surface

Like how use_aws wraps boto3 and use_lerobot wraps lerobot —
but this does it automatically for ANY package.
"""

import ast
import importlib
import inspect as _inspect
import json
import logging
import os
import pkgutil
import subprocess
import sys
import textwrap
import traceback
import types
from io import StringIO
from typing import Any, Dict, List, Optional

from strands import tool

logger = logging.getLogger(__name__)

# ─── Session State ──────────────────────────────────────────────────
# Cache scanned package API maps for fast repeated access
_PACKAGE_CACHE: Dict[str, Dict] = {}

# Registry of dynamically created functions
_FUNCTION_REGISTRY: Dict[str, callable] = {}
_FUNCTION_SOURCE: Dict[str, str] = {}


# ─── Deep Package Scanner ──────────────────────────────────────────


def _safe_import(module_path: str):
    """Import a module, catching heavy side effects."""
    try:
        return importlib.import_module(module_path)
    except Exception:
        return None


def _resolve_dotted_path(target: str):
    """Resolve a dotted path like 'json.dumps' or 'pathlib.Path.read_text' to the actual object."""
    parts = target.split(".")

    # Try importing progressively longer module paths
    for i in range(len(parts), 0, -1):
        module_path = ".".join(parts[:i])
        try:
            obj = importlib.import_module(module_path)
            # Navigate remaining attributes
            for attr_name in parts[i:]:
                obj = getattr(obj, attr_name)
            return obj
        except (ImportError, AttributeError):
            continue

    return None


def _get_signature_str(obj) -> Optional[str]:
    """Get signature string, handling edge cases."""
    try:
        sig = _inspect.signature(obj)
        return str(sig)
    except (ValueError, TypeError):
        return None


def _describe_callable(obj, name: str = "") -> Dict[str, Any]:
    """Describe a callable with full details."""
    info = {
        "name": name or getattr(obj, "__name__", "?"),
        "type": (
            "function"
            if _inspect.isfunction(obj) or _inspect.isbuiltin(obj)
            else (
                "method"
                if _inspect.ismethod(obj)
                else "class" if _inspect.isclass(obj) else "callable"
            )
        ),
    }

    sig = _get_signature_str(obj)
    if sig:
        info["signature"] = sig

        # Extract parameter details
        try:
            real_sig = _inspect.signature(obj)
            params = {}
            for pname, param in real_sig.parameters.items():
                if pname == "self":
                    continue
                p = {"kind": param.kind.name}
                if param.default is not _inspect.Parameter.empty:
                    try:
                        p["default"] = repr(param.default)[:100]
                    except:
                        p["default"] = "..."
                if param.annotation is not _inspect.Parameter.empty:
                    try:
                        p["type"] = (
                            param.annotation.__name__
                            if hasattr(param.annotation, "__name__")
                            else str(param.annotation)[:80]
                        )
                    except:
                        pass
                params[pname] = p
            if params:
                info["params"] = params
        except:
            pass

    # Return type annotation
    try:
        real_sig = _inspect.signature(obj)
        if real_sig.return_annotation is not _inspect.Parameter.empty:
            info["returns"] = str(real_sig.return_annotation)[:100]
    except:
        pass

    # Docstring (first paragraph)
    doc = _inspect.getdoc(obj)
    if doc:
        # First paragraph only
        first_para = doc.split("\n\n")[0].strip()
        info["doc"] = first_para[:300]

    return info


def _scan_module(module, max_depth: int = 2, prefix: str = "", _depth: int = 0) -> Dict[str, Any]:
    """Recursively scan a module for all public APIs."""
    result = {
        "functions": {},
        "classes": {},
        "constants": {},
        "submodules": [],
    }

    if _depth > max_depth:
        return result

    module_name = getattr(module, "__name__", prefix)

    for attr_name in sorted(dir(module)):
        if attr_name.startswith("_"):
            continue

        try:
            obj = getattr(module, attr_name)
        except Exception:
            continue

        full_path = f"{prefix}.{attr_name}" if prefix else attr_name

        if _inspect.isfunction(obj) or _inspect.isbuiltin(obj):
            info = _describe_callable(obj, attr_name)
            info["path"] = full_path
            result["functions"][attr_name] = info

        elif _inspect.isclass(obj):
            # Only include classes actually defined in this module
            if getattr(obj, "__module__", "") == module_name or _depth == 0:
                class_info = _describe_callable(obj, attr_name)
                class_info["path"] = full_path

                # Scan class methods
                methods = {}
                for method_name in sorted(dir(obj)):
                    if method_name.startswith("_") and method_name != "__init__":
                        continue
                    try:
                        method_obj = getattr(obj, method_name)
                        if callable(method_obj):
                            m_info = _describe_callable(method_obj, method_name)
                            m_info["path"] = f"{full_path}.{method_name}"

                            # Tag static/class methods
                            try:
                                raw = _inspect.getattr_static(obj, method_name, None)
                                if isinstance(raw, staticmethod):
                                    m_info["kind"] = "static"
                                elif isinstance(raw, classmethod):
                                    m_info["kind"] = "classmethod"
                            except:
                                pass

                            methods[method_name] = m_info
                    except:
                        continue

                if methods:
                    class_info["methods"] = methods

                result["classes"][attr_name] = class_info

        elif isinstance(obj, types.ModuleType):
            # Only recurse into submodules of the same package
            obj_name = getattr(obj, "__name__", "")
            if obj_name.startswith(module_name.split(".")[0]):
                result["submodules"].append({"name": attr_name, "path": full_path})

    return result


def _deep_scan_package(package_name: str, max_depth: int = 2) -> Dict[str, Any]:
    """Deep scan an entire package — all submodules, all APIs."""

    # Check cache
    cache_key = f"{package_name}:{max_depth}"
    if cache_key in _PACKAGE_CACHE:
        return _PACKAGE_CACHE[cache_key]

    try:
        root_module = importlib.import_module(package_name)
    except ImportError:
        return {"error": f"Package '{package_name}' not installed. Use action='install' first."}

    result = {
        "package": package_name,
        "version": getattr(root_module, "__version__", None),
        "location": getattr(root_module, "__file__", None),
        "doc": (_inspect.getdoc(root_module) or "")[:500],
        "modules": {},
        "all_callables": {},  # flat index: dotted_path → info
    }

    # Scan root module
    root_scan = _scan_module(root_module, max_depth=0, prefix=package_name)
    result["modules"][package_name] = root_scan

    # Index root callables
    for name, info in root_scan["functions"].items():
        result["all_callables"][f"{package_name}.{name}"] = info
    for name, cls_info in root_scan["classes"].items():
        result["all_callables"][f"{package_name}.{name}"] = cls_info
        for method_name, method_info in cls_info.get("methods", {}).items():
            result["all_callables"][f"{package_name}.{name}.{method_name}"] = method_info

    # Walk submodules
    if hasattr(root_module, "__path__"):
        try:
            for importer, modname, ispkg in pkgutil.walk_packages(
                root_module.__path__, prefix=f"{package_name}.", onerror=lambda x: None
            ):
                if any(skip in modname for skip in ["test", "_test", "conftest", "__pycache__"]):
                    continue

                # Limit depth
                depth = modname.count(".") - package_name.count(".")
                if depth > max_depth:
                    continue

                try:
                    submod = importlib.import_module(modname)
                    sub_scan = _scan_module(submod, max_depth=0, prefix=modname)

                    # Only include modules with actual content
                    has_content = (
                        sub_scan["functions"] or sub_scan["classes"] or sub_scan["constants"]
                    )

                    if has_content:
                        result["modules"][modname] = sub_scan

                        # Index into flat callable map
                        for name, info in sub_scan["functions"].items():
                            result["all_callables"][f"{modname}.{name}"] = info
                        for name, cls_info in sub_scan["classes"].items():
                            result["all_callables"][f"{modname}.{name}"] = cls_info
                            for method_name, method_info in cls_info.get("methods", {}).items():
                                result["all_callables"][
                                    f"{modname}.{name}.{method_name}"
                                ] = method_info

                except Exception as e:
                    logger.debug(f"Skip {modname}: {e}")
                    continue

        except Exception as e:
            logger.debug(f"Walk error for {package_name}: {e}")

    # Cache it
    _PACKAGE_CACHE[cache_key] = result

    return result


# ─── Formatters ─────────────────────────────────────────────────────


def _format_scan_summary(scan: Dict) -> str:
    """Format a package scan into a readable summary."""
    parts = []

    pkg = scan["package"]
    parts.append(f"# 📦 {pkg}")
    if scan.get("version"):
        parts.append(f"Version: {scan['version']}")
    if scan.get("doc"):
        parts.append(f"\n{scan['doc']}")

    # Stats
    total_modules = len(scan.get("modules", {}))
    total_callables = len(scan.get("all_callables", {}))
    parts.append(f"\n📊 **{total_modules} modules**, **{total_callables} callables**\n")

    # List modules with their key APIs
    for mod_name, mod_scan in sorted(scan.get("modules", {}).items()):
        funcs = list(mod_scan.get("functions", {}).keys())
        classes = list(mod_scan.get("classes", {}).keys())

        if not funcs and not classes:
            continue

        parts.append(f"## `{mod_name}`")

        if funcs:
            for fname in funcs[:10]:
                finfo = mod_scan["functions"][fname]
                sig = finfo.get("signature", "()")
                doc = finfo.get("doc", "")
                line = f"  - `{fname}{sig}`"
                if doc:
                    line += f" — {doc[:80]}"
                parts.append(line)
            if len(funcs) > 10:
                parts.append(f"  ... and {len(funcs) - 10} more functions")

        if classes:
            for cname in classes[:10]:
                cinfo = mod_scan["classes"][cname]
                sig = cinfo.get("signature", "")
                methods = list(cinfo.get("methods", {}).keys())
                method_count = len(methods)
                line = f"  - **class `{cname}`** ({method_count} methods)"
                if cinfo.get("doc"):
                    line += f" — {cinfo['doc'][:60]}"
                parts.append(line)

                # Show key methods
                for mname in methods[:5]:
                    minfo = cinfo["methods"][mname]
                    msig = minfo.get("signature", "()")
                    parts.append(f"    - `.{mname}{msig}`")
                if method_count > 5:
                    parts.append(f"    ... and {method_count - 5} more methods")

        parts.append("")

    # Usage hint
    parts.append(f"---")
    parts.append(
        f"**Call any function**: `inspect_tool(action='call', target='{pkg}.<path>', args='[...]')`"
    )
    parts.append(f"**Search**: `inspect_tool(action='search', target='{pkg}', query='...')`")
    parts.append(f"**Generate code**: `inspect_tool(action='generate', target='{pkg}.<path>')`")

    return "\n".join(parts)


def _format_callable_detail(info: Dict, target: str) -> str:
    """Format detailed info about a single callable."""
    parts = []

    kind = info.get("type", "callable")
    name = info.get("name", target)
    sig = info.get("signature", "")

    parts.append(f"🔍 **{target}** ({kind})")

    if sig:
        parts.append(f"\n```python\n{name}{sig}\n```")

    if info.get("doc"):
        parts.append(f"\n📖 {info['doc']}")

    if info.get("params"):
        parts.append("\n📋 **Parameters:**")
        for pname, pinfo in info["params"].items():
            line = f"  - `{pname}`"
            if pinfo.get("type"):
                line += f": {pinfo['type']}"
            if pinfo.get("default"):
                line += f" = {pinfo['default']}"
            parts.append(line)

    if info.get("returns"):
        parts.append(f"\n↩️ **Returns:** {info['returns']}")

    if info.get("methods"):
        parts.append(f"\n🔧 **Methods ({len(info['methods'])}):**")
        for mname, minfo in list(info["methods"].items())[:20]:
            msig = minfo.get("signature", "()")
            kind_tag = f" [{minfo['kind']}]" if minfo.get("kind") else ""
            doc_snippet = f" — {minfo['doc'][:60]}" if minfo.get("doc") else ""
            parts.append(f"  - `{mname}{msig}`{kind_tag}{doc_snippet}")
        if len(info["methods"]) > 20:
            parts.append(f"  ... and {len(info['methods']) - 20} more")

    return "\n".join(parts)


def _serialize_result(result: Any) -> str:
    """Convert any result to a readable string."""
    if result is None:
        return "None"
    if isinstance(result, (str, int, float, bool)):
        return repr(result)
    if isinstance(result, bytes):
        return f"bytes({len(result)} bytes)"

    try:
        # Try JSON first
        return json.dumps(result, indent=2, default=str)[:5000]
    except:
        pass

    r = repr(result)
    return r[:5000] if len(r) > 5000 else r


# ─── Code Generator ────────────────────────────────────────────────


def _generate_example(target: str, info: Dict) -> str:
    """Generate a working code example for calling a target."""
    parts = target.split(".")
    package = parts[0]

    kind = info.get("type", "callable")
    sig = info.get("signature", "()")
    params = info.get("params", {})

    lines = [f"# Example: using {target}", ""]

    if kind == "class":
        # Import the class
        module_path = ".".join(parts[:-1])
        class_name = parts[-1]
        lines.append(f"from {module_path} import {class_name}")
        lines.append("")

        # Constructor call
        constructor_args = []
        for pname, pinfo in params.items():
            if pinfo.get("default", "").startswith("REQUIRED") or "default" not in pinfo:
                type_hint = pinfo.get("type", "")
                if "str" in type_hint:
                    constructor_args.append(f'{pname}="..."')
                elif "int" in type_hint or "float" in type_hint:
                    constructor_args.append(f"{pname}=0")
                elif "bool" in type_hint:
                    constructor_args.append(f"{pname}=True")
                elif "dict" in type_hint:
                    constructor_args.append(f"{pname}={{}}")
                elif "list" in type_hint:
                    constructor_args.append(f"{pname}=[]")
                else:
                    constructor_args.append(f"{pname}=...")

        args_str = ", ".join(constructor_args)
        var_name = class_name.lower()
        lines.append(f"{var_name} = {class_name}({args_str})")

        # Show available methods
        methods = info.get("methods", {})
        if methods:
            lines.append("")
            lines.append("# Available methods:")
            for mname, minfo in list(methods.items())[:8]:
                msig = minfo.get("signature", "()")
                lines.append(f"# {var_name}.{mname}{msig}")

    elif kind == "function":
        # Import the function
        module_path = ".".join(parts[:-1])
        func_name = parts[-1]
        lines.append(f"from {module_path} import {func_name}")
        lines.append("")

        # Function call
        call_args = []
        for pname, pinfo in params.items():
            default = pinfo.get("default")
            if default and not default.startswith("REQUIRED"):
                continue  # Skip params with defaults
            type_hint = pinfo.get("type", "")
            if "str" in type_hint:
                call_args.append(f'{pname}="..."')
            elif "int" in type_hint or "float" in type_hint:
                call_args.append(f"{pname}=0")
            elif "bool" in type_hint:
                call_args.append(f"{pname}=True")
            else:
                call_args.append(f"{pname}=...")

        args_str = ", ".join(call_args)
        lines.append(f"result = {func_name}({args_str})")
        lines.append("print(result)")

    else:
        # Generic
        lines.append(f"import {package}")
        lines.append(f"result = {target}()")
        lines.append("print(result)")

    return "\n".join(lines)


# ─── Safe Execution ────────────────────────────────────────────────


def _safe_call(target_path: str, call_args: list = None, call_kwargs: dict = None) -> Dict:
    """Safely call a function by dotted path with args/kwargs."""
    call_args = call_args or []
    call_kwargs = call_kwargs or {}

    obj = _resolve_dotted_path(target_path)
    if obj is None:
        return {"error": f"Cannot resolve '{target_path}'"}

    if not callable(obj):
        return {
            "error": f"'{target_path}' is not callable (type: {type(obj).__name__})",
            "value": repr(obj)[:1000],
        }

    old_stdout, old_stderr = sys.stdout, sys.stderr
    captured_out, captured_err = StringIO(), StringIO()

    result = {"stdout": "", "stderr": "", "return_value": None, "exception": None}

    try:
        sys.stdout, sys.stderr = captured_out, captured_err
        result["return_value"] = obj(*call_args, **call_kwargs)
    except Exception as e:
        result["exception"] = f"{type(e).__name__}: {e}"
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
        result["stdout"] = captured_out.getvalue()
        result["stderr"] = captured_err.getvalue()

    return result


def _safe_exec_code(code: str) -> Dict:
    """Execute arbitrary Python code capturing everything."""
    ns = {"__builtins__": __builtins__}
    ns.update(_FUNCTION_REGISTRY)

    old_stdout, old_stderr = sys.stdout, sys.stderr
    captured_out, captured_err = StringIO(), StringIO()

    result = {"stdout": "", "stderr": "", "return_value": None, "exception": None}

    try:
        sys.stdout, sys.stderr = captured_out, captured_err
        tree = ast.parse(code)

        if tree.body and isinstance(tree.body[-1], ast.Expr):
            last_expr = tree.body.pop()
            if tree.body:
                exec(compile(ast.Module(body=tree.body, type_ignores=[]), "<inspect>", "exec"), ns)
            result["return_value"] = eval(
                compile(ast.Expression(body=last_expr.value), "<inspect>", "eval"), ns
            )
        else:
            exec(compile(tree, "<inspect>", "exec"), ns)
    except Exception as e:
        result["exception"] = f"{type(e).__name__}: {e}\n{traceback.format_exc()}"
    finally:
        sys.stdout, sys.stderr = old_stdout, old_stderr
        result["stdout"] = captured_out.getvalue()
        result["stderr"] = captured_err.getvalue()

    # Extract any new functions
    new_funcs = {}
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = node.name
                if name in ns and (callable(ns[name]) or _inspect.isclass(ns[name])):
                    new_funcs[name] = ns[name]
    except:
        pass

    if new_funcs:
        _FUNCTION_REGISTRY.update(new_funcs)
        for fn_name in new_funcs:
            _FUNCTION_SOURCE[fn_name] = code
        result["registered"] = list(new_funcs.keys())

    return result


def _format_exec_result(result: Dict) -> str:
    """Format execution result."""
    parts = []
    if result.get("stdout"):
        parts.append(f"📤 Output:\n{result['stdout'].rstrip()}")
    if result.get("stderr"):
        parts.append(f"⚠️ Stderr:\n{result['stderr'].rstrip()}")
    if result.get("return_value") is not None:
        parts.append(f"↩️ Return: {_serialize_result(result['return_value'])}")
    if result.get("exception"):
        parts.append(f"❌ {result['exception']}")
    if result.get("registered"):
        parts.append(f"🔧 Registered: {', '.join(result['registered'])}")
    if result.get("error"):
        parts.append(f"❌ {result['error']}")
    if result.get("value"):
        parts.append(f"📦 Value: {result['value']}")
    return "\n\n".join(parts) if parts else "✅ Done (no output)"


# ─── The Tool ───────────────────────────────────────────────────────


@tool
def inspect_tool(
    action: str,
    target: str = None,
    code: str = None,
    query: str = None,
    args: str = None,
    kwargs: str = None,
    name: str = None,
    depth: int = 2,
    pip_package: str = None,
) -> Dict[str, Any]:
    """Turn any Python package into a tool. Deep-scan packages, call any function, generate code.

    Like use_aws wraps boto3 and use_lerobot wraps lerobot — this does it for ANY package automatically.

    Args:
        action: Action to perform:
            - "scan": Deep-scan a package — all modules, classes, functions, signatures
            - "call": Call any function/method by dotted path (e.g., "json.dumps")
            - "inspect": Detailed view of a specific object (class, function, module)
            - "search": Fuzzy search across a package's entire API surface
            - "generate": Generate working code example for a target
            - "exec": Execute Python code and capture output + return value
            - "create": Compile code into a reusable function
            - "list": List registered functions or cached package scans
            - "source": Get source code of any importable object
            - "install": pip install a package and auto-scan it
            - "graph": Full graph analysis — call graph, hotspots, dead code, coupling
            - "connections": Trace all connections for a specific function
            - "hotspots": Most called/referenced functions in a package
            - "unused": Dead code detection — functions defined but never referenced
            - "deps": File-level dependency graph with coupling scores
            - "profile": Runtime profiling — memory timeline, CPU flamegraph, allocations (like clinic.js)
        target: Dotted path — package name for scan, or full path for call/inspect
            Examples: "json", "pathlib.Path", "requests.get", "boto3.client"
        code: Python code to execute (for exec/create actions)
        query: Search query string (for search action)
        args: JSON array of positional arguments (for call action)
        kwargs: JSON object of keyword arguments (for call action)
        name: Override name for created functions
        depth: Max submodule recursion depth for scan (default: 2)
        pip_package: Package name to install (for install action)

    Returns:
        Dict with status and content

    Examples:
        # Scan an entire package
        inspect_tool(action="scan", target="json")
        inspect_tool(action="scan", target="requests", depth=3)

        # Call any function
        inspect_tool(action="call", target="json.dumps", args='[{"hello": "world"}]', kwargs='{"indent": 2}')
        inspect_tool(action="call", target="pathlib.Path.home")
        inspect_tool(action="call", target="os.listdir", args='["."]')

        # Inspect a specific class/function
        inspect_tool(action="inspect", target="pathlib.Path")
        inspect_tool(action="inspect", target="json.JSONEncoder")

        # Search across a package
        inspect_tool(action="search", target="requests", query="post json")
        inspect_tool(action="search", target="pathlib", query="read file")

        # Generate code examples
        inspect_tool(action="generate", target="json.dumps")
        inspect_tool(action="generate", target="pathlib.Path")

        # Execute code
        inspect_tool(action="exec", code="import json; json.dumps({'a': 1}, indent=2)")

        # Install + scan
        inspect_tool(action="install", pip_package="httpx")
    """
    try:
        # ── SCAN: Deep-scan entire package ──────────────────────────
        if action == "scan":
            if not target:
                return _err("target parameter required (package name, e.g., 'json', 'requests')")

            package_name = target.split(".")[0]
            scan = _deep_scan_package(package_name, max_depth=depth)

            if scan.get("error"):
                return _err(scan["error"])

            text = _format_scan_summary(scan)
            return _ok(text)

        # ── CALL: Call any function by dotted path ──────────────────
        elif action == "call":
            if not target:
                return _err("target parameter required (e.g., 'json.dumps', 'os.listdir')")

            call_args = json.loads(args) if args else []
            call_kwargs = json.loads(kwargs) if kwargs else {}

            # Check function registry first
            if target in _FUNCTION_REGISTRY:
                fn = _FUNCTION_REGISTRY[target]
                old_stdout = sys.stdout
                captured = StringIO()
                try:
                    sys.stdout = captured
                    rv = fn(*call_args, **call_kwargs)
                    sys.stdout = old_stdout
                    parts = []
                    stdout = captured.getvalue()
                    if stdout:
                        parts.append(f"📤 Output:\n{stdout.rstrip()}")
                    if rv is not None:
                        parts.append(f"↩️ Return: {_serialize_result(rv)}")
                    return _ok("\n\n".join(parts) if parts else "✅ Done")
                except Exception as e:
                    sys.stdout = old_stdout
                    return _err(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")

            result = _safe_call(target, call_args, call_kwargs)
            return (
                _ok(_format_exec_result(result))
                if not result.get("error")
                else _err(_format_exec_result(result))
            )

        # ── INSPECT: Detailed view of specific object ───────────────
        elif action == "inspect":
            if not target:
                return _err("target parameter required")

            # Try function registry
            if target in _FUNCTION_REGISTRY:
                info = _describe_callable(_FUNCTION_REGISTRY[target], target)
                if target in _FUNCTION_SOURCE:
                    return _ok(
                        _format_callable_detail(info, target)
                        + f"\n\n📝 Source:\n```python\n{_FUNCTION_SOURCE[target]}\n```"
                    )
                return _ok(_format_callable_detail(info, target))

            obj = _resolve_dotted_path(target)
            if obj is None:
                return _err(f"Cannot resolve '{target}'")

            if isinstance(obj, types.ModuleType):
                # Module — do a focused scan
                scan = _scan_module(obj, max_depth=0, prefix=target)
                parts = [f"🔍 **Module: {target}**"]

                doc = _inspect.getdoc(obj)
                if doc:
                    parts.append(f"\n{doc[:500]}")

                if scan["functions"]:
                    parts.append(f"\n⚡ **Functions ({len(scan['functions'])}):**")
                    for fname, finfo in list(scan["functions"].items())[:20]:
                        sig = finfo.get("signature", "()")
                        doc_snippet = f" — {finfo['doc'][:60]}" if finfo.get("doc") else ""
                        parts.append(f"  - `{fname}{sig}`{doc_snippet}")

                if scan["classes"]:
                    parts.append(f"\n🏗️ **Classes ({len(scan['classes'])}):**")
                    for cname, cinfo in list(scan["classes"].items())[:15]:
                        method_count = len(cinfo.get("methods", {}))
                        parts.append(f"  - `{cname}` ({method_count} methods)")

                return _ok("\n".join(parts))

            else:
                info = _describe_callable(obj, target.split(".")[-1])
                text = _format_callable_detail(info, target)

                # Add source if available
                try:
                    source = _inspect.getsource(obj)
                    if len(source) > 3000:
                        source = source[:3000] + "\n# ... [truncated]"
                    text += f"\n\n📝 Source:\n```python\n{source}\n```"
                except:
                    pass

                return _ok(text)

        # ── SEARCH: Fuzzy search across package API ─────────────────
        elif action == "search":
            if not target:
                return _err("target parameter required (package name)")
            if not query:
                return _err("query parameter required")

            package_name = target.split(".")[0]
            scan = _deep_scan_package(package_name, max_depth=depth)

            if scan.get("error"):
                return _err(scan["error"])

            query_terms = query.lower().split()
            matches = []

            for path, info in scan.get("all_callables", {}).items():
                # Score based on name, doc, and signature matching
                text_to_search = " ".join(
                    [
                        path.lower(),
                        (info.get("doc") or "").lower(),
                        " ".join(info.get("params", {}).keys()),
                    ]
                ).lower()

                score = sum(1 for term in query_terms if term in text_to_search)

                if score > 0:
                    matches.append((score, path, info))

            matches.sort(key=lambda x: (-x[0], x[1]))

            if not matches:
                return _ok(
                    f"No matches for '{query}' in {package_name}. Try different search terms."
                )

            parts = [
                f"🔎 Search results for **'{query}'** in `{package_name}` ({len(matches)} matches):\n"
            ]

            for score, path, info in matches[:20]:
                sig = info.get("signature", "")
                kind = info.get("type", "?")
                doc_snippet = f" — {info['doc'][:80]}" if info.get("doc") else ""
                parts.append(f"  {'⭐' * min(score, 3)} `{path}{sig}` [{kind}]{doc_snippet}")

            if len(matches) > 20:
                parts.append(f"\n  ... and {len(matches) - 20} more matches")

            parts.append(f"\n**Inspect**: `inspect_tool(action='inspect', target='<path>')`")
            parts.append(f"**Call**: `inspect_tool(action='call', target='<path>', args='[...]')`")

            return _ok("\n".join(parts))

        # ── GENERATE: Generate working code example ─────────────────
        elif action == "generate":
            if not target:
                return _err("target parameter required")

            obj = _resolve_dotted_path(target)
            if obj is None:
                return _err(f"Cannot resolve '{target}'")

            info = _describe_callable(obj, target.split(".")[-1])
            example_code = _generate_example(target, info)

            text = f"💡 Generated code for `{target}`:\n\n```python\n{example_code}\n```"
            text += f"\n\n**Run it**: `inspect_tool(action='exec', code=<paste above>)`"

            return _ok(text)

        # ── EXEC: Execute Python code ───────────────────────────────
        elif action == "exec":
            if not code:
                return _err("code parameter required")

            result = _safe_exec_code(code)
            return _ok(_format_exec_result(result))

        # ── CREATE: Compile into reusable function ──────────────────
        elif action == "create":
            if not code:
                return _err("code parameter required")

            code = textwrap.dedent(code)

            try:
                tree = ast.parse(code)
            except SyntaxError as e:
                return _err(f"Syntax error: {e}")

            has_def = any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
                for n in tree.body
            )

            if not has_def:
                fn_name = name or "generated_fn"
                lines = code.strip().split("\n")
                try:
                    last_tree = ast.parse(lines[-1].strip())
                    if last_tree.body and isinstance(last_tree.body[0], ast.Expr):
                        lines[-1] = f"return {lines[-1].strip()}"
                except:
                    pass
                code = f"def {fn_name}():\n" + textwrap.indent("\n".join(lines), "    ")

            result = _safe_exec_code(code)

            if result.get("exception"):
                return _err(f"Failed:\n{result['exception']}")

            if result.get("registered"):
                names = result["registered"]
                summaries = []
                for fn_name in names:
                    fn = _FUNCTION_REGISTRY[fn_name]
                    sig = _get_signature_str(fn) or "()"
                    summaries.append(f"  ✅ `{fn_name}{sig}`")

                text = f"🔧 Created {len(names)} function(s):\n" + "\n".join(summaries)
                text += f"\n\n```python\n{code}\n```"
                return _ok(text)

            return _err("No function/class found. Use action='exec' for bare code.")

        # ── LIST: Show registry and cache ───────────────────────────
        elif action == "list":
            parts = []

            if _PACKAGE_CACHE:
                parts.append("📦 **Scanned Packages:**")
                for key, scan in _PACKAGE_CACHE.items():
                    pkg = scan.get("package", key)
                    n_callables = len(scan.get("all_callables", {}))
                    n_modules = len(scan.get("modules", {}))
                    parts.append(f"  - `{pkg}` — {n_modules} modules, {n_callables} callables")
                parts.append("")

            if _FUNCTION_REGISTRY:
                parts.append("🔧 **Registered Functions:**")
                for fn_name, fn_obj in _FUNCTION_REGISTRY.items():
                    sig = _get_signature_str(fn_obj) or "()"
                    parts.append(f"  - `{fn_name}{sig}`")
                parts.append("")

            if not parts:
                return _ok(
                    "Empty. Use `action='scan'` to scan a package or `action='create'` to make functions."
                )

            return _ok("\n".join(parts))

        # ── SOURCE: Get source code ─────────────────────────────────
        elif action == "source":
            if not target:
                return _err("target parameter required")

            if target in _FUNCTION_SOURCE:
                return _ok(f"```python\n{_FUNCTION_SOURCE[target]}\n```")

            obj = _resolve_dotted_path(target)
            if obj is None:
                return _err(f"Cannot resolve '{target}'")

            try:
                source = _inspect.getsource(obj)
                return _ok(f"```python\n{source}\n```")
            except (OSError, TypeError):
                return _err(f"Source not available for '{target}' (C extension or built-in)")

        # ── INSTALL: pip install + auto-scan ────────────────────────
        elif action == "install":
            pkg = pip_package or target
            if not pkg:
                return _err("pip_package or target parameter required")

            try:
                result = subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )

                if result.returncode != 0:
                    return _err(f"pip install failed:\n{result.stderr}")

                # Auto-scan the installed package
                module_name = pkg.split("[")[0].replace("-", "_").lower()

                try:
                    scan = _deep_scan_package(module_name, max_depth=depth)
                    if scan.get("error"):
                        return _ok(
                            f"✅ Installed `{pkg}` (import name may differ)\n\n{scan['error']}"
                        )
                    text = f"✅ Installed `{pkg}`\n\n{_format_scan_summary(scan)}"
                except:
                    text = f"✅ Installed `{pkg}` (scan failed — try `action='scan', target='<import_name>'`)"

                return _ok(text)

            except subprocess.TimeoutExpired:
                return _err(f"Install timed out for '{pkg}'")

        # ── PROFILE: Runtime profiling (like clinic.js) ─────────────
        elif action == "profile":
            if not code:
                return _err("code parameter required for profile")
            from strands_inspect._profile import handle_profile_action

            return handle_profile_action(code=code, top_n=20, sort_by="cumulative")

        # ── Graph Analysis Actions (delegated to _graph module) ───
        elif action == "graph":
            if not target:
                return _err("target parameter required (package name)")
            from strands_inspect._graph import handle_graph_action

            return handle_graph_action(target, query=query, depth=depth)

        elif action == "connections":
            if not target:
                return _err("target required — package.function (e.g., strands.Agent)")
            from strands_inspect._graph import handle_connections_action

            return handle_connections_action(target)

        elif action == "hotspots":
            if not target:
                return _err("target parameter required (package name)")
            from strands_inspect._graph import handle_hotspots_action

            return handle_hotspots_action(target)

        elif action == "unused":
            if not target:
                return _err("target parameter required (package name)")
            from strands_inspect._graph import handle_unused_action

            return handle_unused_action(target)

        elif action == "deps":
            if not target:
                return _err("target parameter required (package name)")
            from strands_inspect._graph import handle_deps_action

            return handle_deps_action(target)

        else:
            return _err(
                f"Unknown action: {action}. Valid: scan, call, inspect, search, generate, exec, create, list, source, install, profile, graph, connections, hotspots, unused, deps"
            )

    except Exception as e:
        return _err(f"{type(e).__name__}: {e}\n{traceback.format_exc()}")


# ── Helpers ─────────────────────────────────────────────────────────


def _ok(text: str) -> Dict:
    return {"status": "success", "content": [{"text": text}]}


def _err(text: str) -> Dict:
    return {"status": "error", "content": [{"text": text}]}

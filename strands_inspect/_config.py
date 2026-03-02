"""
Configuration file support for strands-inspect.

Loads settings from (in priority order):
  1. .strands-inspect.toml  (project root)
  2. ~/.strands_inspect/config.toml  (user home)
  3. Environment variables (STRANDS_INSPECT_*)

Example .strands-inspect.toml:

    [watch]
    default_policy = "sandbox"
    dump = true
    dump_dir = "~/.strands_inspect"
    profile = true
    print_summary = true
    timeline_interval_ms = 50

    [watch.policies.my_policy]
    "file.read" = "log"
    "file.write" = "deny"
    "network" = "deny"
    "subprocess" = "deny"
    "import" = "log"

    [lock]
    timeout = 30

    [tool]
    default_depth = 2
    cache_enabled = true
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

# Python 3.11+ has tomllib, older versions need tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

_CONFIG_CACHE: Optional[Dict[str, Any]] = None
_CONFIG_LOADED = False


def _find_config_file() -> Optional[Path]:
    """Find the nearest config file, walking up from cwd."""
    # 1. Check cwd and parents
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".strands-inspect.toml"
        if candidate.exists():
            return candidate
        # Stop at home or root
        if parent == Path.home() or parent == parent.parent:
            break

    # 2. Check user home
    home_config = Path.home() / ".strands_inspect" / "config.toml"
    if home_config.exists():
        return home_config

    return None


def load_config(force_reload: bool = False) -> Dict[str, Any]:
    """Load configuration from file and environment.

    Returns a dict with sections: watch, lock, tool, policies.
    """
    global _CONFIG_CACHE, _CONFIG_LOADED

    if _CONFIG_LOADED and not force_reload and _CONFIG_CACHE is not None:
        return _CONFIG_CACHE

    config: Dict[str, Any] = {
        "watch": {
            "default_policy": "allow_all",
            "dump": True,
            "dump_dir": None,
            "profile": True,
            "print_summary": True,
            "timeline_interval_ms": 50,
        },
        "lock": {
            "timeout": 30,
        },
        "tool": {
            "default_depth": 2,
            "cache_enabled": True,
        },
        "policies": {},
    }

    # Load from file
    if tomllib is not None:
        config_file = _find_config_file()
        if config_file:
            try:
                with open(config_file, "rb") as f:
                    file_config = tomllib.load(f)
                _deep_merge(config, file_config)
            except Exception:
                pass  # Silently ignore bad config files

    # Override from environment
    env_map = {
        "STRANDS_INSPECT_DEFAULT_POLICY": ("watch", "default_policy"),
        "STRANDS_INSPECT_DUMP": ("watch", "dump"),
        "STRANDS_INSPECT_DUMP_DIR": ("watch", "dump_dir"),
        "STRANDS_INSPECT_PROFILE": ("watch", "profile"),
        "STRANDS_INSPECT_PRINT_SUMMARY": ("watch", "print_summary"),
        "STRANDS_INSPECT_LOCK_TIMEOUT": ("lock", "timeout"),
        "STRANDS_INSPECT_TOOL_DEPTH": ("tool", "default_depth"),
    }

    for env_key, (section, key) in env_map.items():
        val = os.getenv(env_key)
        if val is not None:
            # Type coerce
            existing = config[section].get(key)
            if isinstance(existing, bool):
                config[section][key] = val.lower() in ("true", "1", "yes")
            elif isinstance(existing, int):
                try:
                    config[section][key] = int(val)
                except ValueError:
                    pass
            else:
                config[section][key] = val

    _CONFIG_CACHE = config
    _CONFIG_LOADED = True
    return config


def get_watch_defaults() -> Dict[str, Any]:
    """Get default kwargs for @watch from config."""
    cfg = load_config()
    w = cfg.get("watch", {})
    return {
        "policy": w.get("default_policy", "allow_all"),
        "dump": w.get("dump", True),
        "dump_dir": w.get("dump_dir"),
        "profile": w.get("profile", True),
        "print_summary": w.get("print_summary", True),
        "timeline_interval_ms": w.get("timeline_interval_ms", 50),
    }


def get_named_policy(name: str) -> Optional[Dict[str, Any]]:
    """Get a named policy from config file.

    Example config:
        [watch.policies.strict_api]
        "file.write" = "deny"
        "network" = { action = "allow", hosts = ["api.openai.com"] }

    Usage:
        @watch(policy="strict_api")  # loads from config
    """
    cfg = load_config()
    policies = cfg.get("watch", {}).get("policies", cfg.get("policies", {}))
    return policies.get(name)


def get_lock_defaults() -> Dict[str, Any]:
    """Get default kwargs for @lock from config."""
    cfg = load_config()
    return cfg.get("lock", {"timeout": 30})


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge override into base."""
    for key, value in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(value, dict):
            _deep_merge(base[key], value)
        else:
            base[key] = value
    return base

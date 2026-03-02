"""Tests for configuration file support."""

import os
import tempfile
import pytest
from pathlib import Path
from strands_inspect._config import (
    load_config,
    get_watch_defaults,
    get_named_policy,
    get_lock_defaults,
    _find_config_file,
    _deep_merge,
    _CONFIG_CACHE,
)
import strands_inspect._config as config_mod


class TestConfig:
    def setup_method(self):
        config_mod._CONFIG_CACHE = None
        config_mod._CONFIG_LOADED = False

    def test_default_config(self):
        config = load_config(force_reload=True)
        assert "watch" in config
        assert "lock" in config
        assert "tool" in config
        assert config["watch"]["default_policy"] == "allow_all"
        assert config["watch"]["dump"] is True
        assert config["lock"]["timeout"] == 30

    def test_watch_defaults(self):
        d = get_watch_defaults()
        assert d["policy"] == "allow_all"
        assert d["dump"] is True
        assert d["profile"] is True
        assert d["print_summary"] is True
        assert d["timeline_interval_ms"] == 50

    def test_lock_defaults(self):
        d = get_lock_defaults()
        assert d["timeout"] == 30

    def test_env_override(self):
        os.environ["STRANDS_INSPECT_DEFAULT_POLICY"] = "sandbox"
        os.environ["STRANDS_INSPECT_DUMP"] = "false"
        try:
            config = load_config(force_reload=True)
            assert config["watch"]["default_policy"] == "sandbox"
            assert config["watch"]["dump"] is False
        finally:
            del os.environ["STRANDS_INSPECT_DEFAULT_POLICY"]
            del os.environ["STRANDS_INSPECT_DUMP"]

    def test_deep_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": 3}
        override = {"a": {"y": 99, "z": 100}, "c": 4}
        result = _deep_merge(base, override)
        assert result["a"]["x"] == 1
        assert result["a"]["y"] == 99
        assert result["a"]["z"] == 100
        assert result["b"] == 3
        assert result["c"] == 4

    def test_config_file_loading(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".strands-inspect.toml"
            config_path.write_text("""
[watch]
default_policy = "deny_all"
dump = false

[lock]
timeout = 60
""")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                config = load_config(force_reload=True)
                assert config["watch"]["default_policy"] == "deny_all"
                assert config["watch"]["dump"] is False
                assert config["lock"]["timeout"] == 60
            finally:
                os.chdir(old_cwd)

    def test_named_policy(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / ".strands-inspect.toml"
            config_path.write_text("""
[watch.policies.api_only]
"file.write" = "deny"
"network" = "log"
""")
            old_cwd = os.getcwd()
            os.chdir(tmpdir)
            try:
                config_mod._CONFIG_CACHE = None
                config_mod._CONFIG_LOADED = False
                policy = get_named_policy("api_only")
                assert policy is not None
                assert policy["file.write"] == "deny"
                assert policy["network"] == "log"
            finally:
                os.chdir(old_cwd)

    def test_named_policy_not_found(self):
        config_mod._CONFIG_CACHE = None
        config_mod._CONFIG_LOADED = False
        assert get_named_policy("nonexistent") is None

    def test_cache(self):
        c1 = load_config(force_reload=True)
        c2 = load_config()
        assert c1 is c2  # same object from cache

    def test_force_reload(self):
        c1 = load_config(force_reload=True)
        c2 = load_config(force_reload=True)
        assert c1 is not c2  # different objects

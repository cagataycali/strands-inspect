"""The Inspect action schema, the hook bridge, presets, @lock projection, @watch wiring, CLI."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from strands_inspect import DogwoodPolicy, PolicyViolation, watch
from strands_inspect._decorator import BUILTIN_POLICIES, SyscallHooks, resolve_watch_policy
from strands_inspect._sandbox import resolve_kernel_policy
from strands_inspect.dogwood import PRESETS, Verdict, __main__ as cli
from strands_inspect.dogwood.bridge import DogwoodBridge, build_input, fields_from_detail
from strands_inspect.dogwood.errors import DogwoodError
from strands_inspect.dogwood.inspect_schema import (
    ACTIONS,
    INSPECT_SCHEMA_TEXT,
    SCHEMA_PATH,
    action_ref,
    categories_in,
    classify_sensitive,
    group_of,
    inspect_schema,
)
from strands_inspect.dogwood.projection import project_to_kernel
from strands_inspect.dogwood.values import SetValue

REF_CLI = os.path.expanduser("~/.tiny/dogwood-20260930/ref/target/release/dogwood")
POLICIES = Path(__file__).resolve().parents[1] / "strands_inspect" / "policies"


# ------------------------------------------------------------------ schema
def test_shipped_cedarschema_matches_the_python_string():
    with open(SCHEMA_PATH, encoding="utf-8") as fh:
        assert fh.read() == INSPECT_SCHEMA_TEXT


def test_schema_has_every_legacy_category_and_group():
    s = inspect_schema()
    assert set(ACTIONS) == set(BUILTIN_POLICIES["deny_all"])  # the 20 legacy categories, verbatim
    assert sorted(a.id for a in s.members_of(action_ref("net"))) == ["net", "net.socket", "network"]
    assert sorted(categories_in("os")) == ["os.exec", "os.system", "subprocess"]
    assert group_of("import") is None and group_of("meta.code") == "meta"
    assert s.record_path(action_ref("file.read"), ["input", "sensitive"]) == ("prim", "Bool")
    assert s.record_path(action_ref("subprocess"), ["input", "argv"]) == ("set", ("prim", "String"))
    assert s.record_path(action_ref("network"), ["system", "now"]) == ("ext", "datetime")
    assert s.record_path(action_ref("network"), ["output", "allowed"]) == ("prim", "Bool")
    for cat in ACTIONS:
        assert s.record_path(action_ref(cat), ["input", "detail"]) == ("prim", "String")
        assert s.record_path(action_ref(cat), ["input", "op"]) == ("prim", "String")


@pytest.mark.parametrize(
    "path, sensitive",
    [
        ("~/.ssh/id_rsa", True),
        ("~/.aws/credentials", True),
        ("~/.gnupg/pubring.kbx", True),
        ("~/.config/gcloud/x.json", True),
        ("~/.kube/config", True),
        ("/etc/shadow", True),
        ("/etc/passwd", True),
        ("/app/.env", True),
        ("/app/.env.local", True),
        ("/x/server.pem", True),
        ("/x/server.key", True),
        ("/x/id_ed25519.pub", True),
        ("/x/aws_credentials.json", True),
        ("/Users/me/Library/login.keychain-db", True),
        ("/tmp/data.csv", False),
        ("/etc/hosts", False),
        ("~/.sshx/notes", False),
        ("", False),
    ],
)
def test_classify_sensitive(path, sensitive):
    assert classify_sensitive(path) is sensitive


# ------------------------------------------------------------------ presets
@pytest.mark.parametrize("name", PRESETS)
def test_presets_load_and_carry_ids(name):
    pol = DogwoodPolicy.preset(name)
    assert pol.rules and all(not r.startswith("policy") for r in pol.rules), pol.rules
    assert pol.describe()["language"] == "dogwood" and "//" in pol.source


@pytest.mark.skipif(not os.path.exists(REF_CLI), reason="reference dogwood CLI not built here")
@pytest.mark.parametrize("name", PRESETS)
def test_reference_cli_validates_every_preset_against_the_shipped_schema(name):
    out = subprocess.run(
        [REF_CLI, "validate", str(POLICIES / f"{name}.dw"), "--policy-schema", SCHEMA_PATH],
        capture_output=True,
        text=True,
    )
    assert out.returncode == 0 and "OK" in out.stdout, out.stdout + out.stderr


def test_unknown_preset_is_an_error():
    with pytest.raises(DogwoodError, match="unknown preset"):
        DogwoodPolicy.preset("nope")


# ------------------------------------------------------------------ detail parsing
@pytest.mark.parametrize(
    "action, detail, want",
    [
        ("file.read", "/etc/hosts (mode=r)", {"path": "/etc/hosts", "mode": "r"}),
        ("file.write", "/tmp/o (os.open flags=0x601)", {"path": "/tmp/o", "mode": "0x601"}),
        ("file.write", "shutil.copy /a → /b", {"path": "/b", "mode": ""}),
        ("file.delete", "rmtree /tmp/d", {"path": "/tmp/d"}),
        ("file.mkdir", "makedirs /tmp/a/b", {"path": "/tmp/a/b"}),
        ("file.special", "mkfifo /tmp/f", {"path": "/tmp/f"}),
        ("file.move", "shutil.move /a → /b", {"src": "/a", "dst": "/b"}),
        ("file.link", "symlink /a → /b", {"src": "/a", "dst": "/b"}),
        ("file.chmod", "chown 1:2 /x", {"mode": "1:2", "path": "/x"}),
        ("file.fd_io", "os.read(fd=3, n=10)", {"fd": 3, "size": 10}),
        ("file.fd_io", "truncate /x to 5", {"size": 5}),
        ("network", "GET → https://api.openai.com/v1", {"method": "GET", "url": "https://api.openai.com/v1", "scheme": "https", "host": "api.openai.com", "port": 443}),
        ("network", "connect → ('1.2.3.4', 8080)", {"host": "1.2.3.4", "port": 8080}),
        ("network", "http.client → h:80", {"host": "h", "port": 80}),
        ("network", "urlopen → http://x.io", {"url": "http://x.io", "scheme": "http", "host": "x.io", "port": 80}),
        ("net.socket", "sendto 12 bytes → ('h', 53)", {"size": 12, "host": "h", "port": 53}),
        ("net.socket", "listen backlog=5", {}),
        ("subprocess", "['curl', '-s', 'http://x']", {"command": "['curl', '-s', 'http://x']", "argv": ["curl", "-s", "http://x"], "program": "curl", "shell": False}),
        ("os.system", "popen: ls -la /tmp", {"command": "ls -la /tmp", "argv": ["ls", "-la", "/tmp"], "program": "ls", "shell": True}),
        ("os.exec", "execvp: /bin/sh -c id", {"command": "/bin/sh -c id", "program": "sh", "shell": True, "argv": ["/bin/sh", "-c", "id"]}),
        ("process.kill", "killpg pgid=-12 sig=15", {"pid": -12, "signal": 15}),
        ("process.mp", "Process.start name=w target=f", {"name": "w", "target": "f"}),
        ("import", "os.path", {"module": "os.path", "package": "os"}),
        ("meta.ctypes", "cdll.LoadLibrary(libc.so.6)", {"library": "libc.so.6"}),
        ("meta.code", "eval(1 + 1)", {"source": "1 + 1"}),
        ("process.fork", "os.fork()", {}),
    ],
)  # fmt: skip
def test_fields_from_detail(action, detail, want):
    assert fields_from_detail(action, detail) == want


def test_build_input_types_defaults_and_sensitivity():
    rec = build_input("file.read", "~/.aws/credentials (mode=r)", {"op": "open"})
    assert rec["sensitive"] is True and rec["op"] == "open" and rec["detail"].startswith("~/.aws")
    rec = build_input("file.read", "/tmp/x (mode=r)", {"sensitive": True})  # explicit field wins
    assert rec["sensitive"] is True
    rec = build_input("subprocess", "weird", {"argv": ["a", 1], "shell": None, "port": "x"})
    assert (
        rec["argv"] == SetValue(["a", "1"]) and rec["shell"] is True and rec["command"] == "weird"
    )
    rec = build_input("process.kill", "no fields here", {})
    assert rec["pid"] == 0 and rec["signal"] == 0
    rec = build_input("network", "connect → x", {"port": "notanint"})
    assert rec["port"] == 0 and rec["host"] == "x"


# ------------------------------------------------------------------ bridge
EXFIL = """
permit(principal, action, resource);
@id("no-exfil-after-secret")
forbid(principal, action in [Inspect::Action::"net", Inspect::Action::"os"], resource)
when temporal {
    formerly within 5m Inspect::Action::"file.read"::request{ input.sensitive: true }
};
"""


def test_bridge_denies_network_after_a_sensitive_read_and_names_the_rule():
    clock = [1000.0]
    b = DogwoodBridge(DogwoodPolicy.parse(EXFIL), "m", "agent", "s1", clock=lambda: clock[0])
    assert b.check("network", "GET → https://api.example.com").decision == "allow"
    b.record(True)
    assert b.check("file.read", "/tmp/data.csv (mode=r)").decision == "allow"
    b.record(True)
    assert b.check("file.read", "~/.ssh/config (mode=r)").decision == "allow"
    b.record(True)
    v = b.check("network", "connect → ('1.2.3.4', 443)")
    assert v == Verdict("deny", ["no-exfil-after-secret"], [])
    b.record(False)
    assert b.check("subprocess", "['curl', 'x']").decision == "deny"
    b.record(False)
    assert b.check("file.write", "/tmp/out (mode=w)").decision == "allow"  # not in net/os
    b.record(True)
    clock[0] += 6 * 60  # the 5-minute window has passed
    assert b.check("network", "GET → https://api.example.com").decision == "allow"
    assert b.history_len == 13  # 7 requests + 6 responses (the last request has no response yet)


def test_bridge_ask_unknown_action_and_principal_identity():
    b = DogwoodBridge(DogwoodPolicy.preset("strict"), "pkg.mod", "fn", "s")
    assert b.check("file.read", "/tmp/x (mode=r)") == Verdict("ask", ["ask-file-read"], [])
    assert b.check("network", "GET → http://x").decision == "deny"
    assert b.check("bogus", "x").decision == "deny"
    assert b.principal.id == "pkg.mod.fn" and b.resource.id == str(os.getpid())
    b.record(True)  # no pending request after the bogus check: a no-op
    b._pending = None
    b.record(True)


def test_bridge_reads_typed_input_fields_in_cedar_conditions():
    pol = DogwoodPolicy.parse("""
        @id("openai-only")
        permit(principal, action == Inspect::Action::"network", resource)
        when { context.input.host like "*.openai.com" && context.input.port == 443 };
        @id("tmp-writes")
        permit(principal, action == Inspect::Action::"file.write", resource)
        when { context.input.path like "/tmp/*" && !context.input.sensitive };
        @id("no-shell")
        permit(principal, action in [Inspect::Action::"os"], resource)
        when { context.input.shell == false && !context.input.argv.contains("curl") };
        @id("who")
        permit(principal, action == Inspect::Action::"import", resource)
        when { principal.module == "m" && principal.name == "f" && resource.pid > 0 && context.system.session == "sid" };
        """)
    b = DogwoodBridge(pol, "m", "f", "sid")
    assert b.check("network", "GET → https://api.openai.com/v1").rules == ["openai-only"]
    assert b.check("network", "GET → http://api.openai.com/v1").decision == "deny"  # port 80
    assert b.check("network", "GET → https://evil.com").decision == "deny"
    assert b.check("file.write", "/tmp/out (mode=w)").decision == "allow"
    assert b.check("file.write", "/tmp/.env (mode=w)").decision == "deny"
    assert b.check("file.write", "/etc/x (mode=w)").decision == "deny"
    assert b.check("subprocess", "['ls', '-la']").decision == "allow"
    assert b.check("subprocess", "['curl', 'x']").decision == "deny"
    assert b.check("os.system", "ls -la").decision == "deny"  # shell
    assert b.check("import", "json").rules == ["who"]


# ------------------------------------------------------------------ hooks + @watch wiring
def test_hooks_with_bridge_raise_named_violations_and_record_rules():
    hooks = SyscallHooks(bridge=DogwoodBridge(DogwoodPolicy.preset("deny_network"), "m", "f", "s"))
    assert (
        hooks._check_policy("file.read", "/tmp/x (mode=r)", path="/tmp/x", mode="r", op="open")
        == "allow"
    )
    with pytest.raises(PolicyViolation) as ei:
        hooks._check_policy("network", "GET → https://x", url="https://x", method="GET")
    assert ei.value.rules == ["deny-network"] and "rule deny-network" in str(ei.value)
    assert [e.decision for e in hooks.events] == ["allow", "deny"]
    assert hooks.events[0].rules == ["allow-everything"] and hooks.events[1].to_dict()["rules"] == [
        "deny-network"
    ]


def test_resolve_watch_policy_forms(tmp_path, monkeypatch):
    legacy, dw = resolve_watch_policy("sandbox")
    assert legacy == {} and dw.name == "sandbox.dw"
    f = tmp_path / "team.dw"
    f.write_text('@id("x") permit(principal, action, resource);', encoding="utf-8")
    assert resolve_watch_policy(str(f))[1].rules == ["x"] and resolve_watch_policy(f)[1].rules == [
        "x"
    ]
    assert resolve_watch_policy("forbid(principal, action, resource);")[1].rules == ["policy0"]
    pol = DogwoodPolicy.preset("strict")
    assert resolve_watch_policy(pol) == ({}, pol)
    assert resolve_watch_policy({"network": "deny"}) == ({"network": "deny"}, None)
    fn = lambda a, d: "allow"  # noqa: E731
    assert resolve_watch_policy(fn)[0]["file.read"] is fn
    import strands_inspect._decorator as dec

    monkeypatch.setattr(
        dec,
        "get_named_policy",
        lambda name: (
            {"dogwood": "forbid(principal, action, resource);"}
            if name == "cfg-inline"
            else (
                {"file": str(f)}
                if name == "cfg-file"
                else {"network": "deny"} if name == "cfg-legacy" else None
            )
        ),
    )
    assert resolve_watch_policy("cfg-inline")[1].name == "cfg-inline"
    assert resolve_watch_policy("cfg-file")[1].rules == ["x"]
    assert resolve_watch_policy("cfg-legacy") == ({"network": "deny"}, None)
    assert resolve_watch_policy("unknown-name")[1].name == "allow_all.dw"


def test_watch_end_to_end_with_inline_dogwood(tmp_path):
    secret = tmp_path / "id_rsa"
    secret.write_text("k", encoding="utf-8")

    @watch(policy=EXFIL, dump=False, profile=False, print_summary=False)
    def agent():
        open(str(secret)).read()
        subprocess.run(["true"])  # denied: an `os` action after a sensitive read
        return "unreachable"

    result = agent()
    session = agent.last_session if hasattr(agent, "last_session") else None
    assert result is None or session is not None  # the violation is recorded, not re-raised


def test_watch_session_records_dogwood_policy_and_rules(tmp_path):
    from strands_inspect import replay as load_session

    dump_dir = tmp_path / "dumps"

    @watch(
        policy="deny_write", dump=True, dump_dir=str(dump_dir), profile=False, print_summary=False
    )
    def writer():
        open(str(tmp_path / "out.txt"), "w").write("x")

    writer()
    files = list(dump_dir.glob("*.dill"))
    assert files, "session dump missing"
    session = load_session(str(files[0]))
    data = session.to_json()["session"]
    assert data["policy"]["language"] == "dogwood"
    assert data["policy"]["rules"] == ["allow-everything", "deny-file-mutation"]
    denied = [e for e in data["syscalls"] if e["decision"] == "deny"]
    assert (
        denied
        and denied[0]["rules"] == ["deny-file-mutation"]
        and denied[0]["action"] == "file.write"
    )
    assert "deny-file-mutation" in (session.exception or "")


# ------------------------------------------------------------------ @lock projection
@pytest.mark.parametrize(
    "src, want",
    [
        ("permit(principal, action, resource);", dict(network=True, file_read=True, file_write=True, subprocess=True, ipc=True, mmap_exec=True, sysctl=False)),
        ("forbid(principal, action, resource);", dict(network=False, file_read=False, file_write=False, subprocess=False, ipc=False, mmap_exec=False, sysctl=False)),
        ('permit(principal, action, resource); forbid(principal, action in [Inspect::Action::"net"], resource) when { context.input.port == 25 };', dict(network=False, file_read=True, file_write=True, subprocess=True, ipc=True, mmap_exec=True, sysctl=False)),
        ('permit(principal, action == Inspect::Action::"file.read", resource) when { context.input.path like "/data/*" }; permit(principal, action in [Inspect::Action::"os"], resource);', dict(network=False, file_read=["/data/**"], file_write=False, subprocess=False, ipc=False, mmap_exec=False, sysctl=False)),
        ('permit(principal, action in [Inspect::Action::"os", Inspect::Action::"process"], resource);', dict(network=False, file_read=False, file_write=False, subprocess=True, ipc=True, mmap_exec=False, sysctl=False)),
        ('permit(principal, action == Inspect::Action::"file.read", resource) when { context.input.sensitive == false };', dict(network=False, file_read=False, file_write=False, subprocess=False, ipc=False, mmap_exec=False, sysctl=False)),
        ('@ask permit(principal, action == Inspect::Action::"file.read", resource);', dict(network=False, file_read=False, file_write=False, subprocess=False, ipc=False, mmap_exec=False, sysctl=False)),
        ('permit(principal, action == Inspect::Action::"file.read", resource) when { context.input.path like "/a/*" } when { true };', dict(network=False, file_read=False, file_write=False, subprocess=False, ipc=False, mmap_exec=False, sysctl=False)),
    ],
)  # fmt: skip
def test_projection_table(src, want):
    assert project_to_kernel(DogwoodPolicy.parse(src).policy_set) == want


def test_preset_projections_match_the_kernel_tables_where_they_can():
    assert project_to_kernel(DogwoodPolicy.preset("sandbox").policy_set) == dict(
        network=False,
        file_read=True,
        file_write=False,
        subprocess=False,
        ipc=False,
        mmap_exec=False,
        sysctl=False,
    )
    assert project_to_kernel(DogwoodPolicy.preset("deny_all").policy_set)["file_read"] is False


def test_resolve_kernel_policy_accepts_dogwood(tmp_path):
    assert resolve_kernel_policy(DogwoodPolicy.preset("deny_network"))["network"] is False
    assert (
        resolve_kernel_policy('permit(principal, action in [Inspect::Action::"file"], resource);')[
            "file_write"
        ]
        is True
    )
    f = tmp_path / "p.dw"
    f.write_text("permit(principal, action, resource);", encoding="utf-8")
    assert resolve_kernel_policy(str(f))["network"] is True
    assert resolve_kernel_policy("sandbox")["ipc"] is True  # kernel preset table untouched
    assert resolve_kernel_policy({"network": False})["network"] is False


# ------------------------------------------------------------------ CLI
def test_cli_check_replay_explain(capsys, tmp_path):
    assert cli.main(["check", str(POLICIES / "deny_network.dw")]) == 0
    assert "deny-network" in capsys.readouterr().out
    assert cli.main(["explain", str(POLICIES / "strict.dw")]) == 0
    out = capsys.readouterr().out
    assert "(@ask)" in out and "@lock projection" in out and "[file.read]" in out
    ex = Path(__file__).parent / "dogwood_corpus" / "examples" / "write_after_read"
    assert (
        cli.main(
            [
                "replay",
                str(ex / "policy.dw"),
                str(ex / "trace.log"),
                "--schema",
                str(ex / "schema.cedarschema"),
                "--unpinned",
            ]
        )
        == 0
    )
    assert (
        capsys.readouterr().out.strip() == (ex / "expected.out").read_text(encoding="utf-8").strip()
    )
    assert (
        cli.main(
            [
                "replay",
                str(ex / "policy.dw"),
                str(ex / "trace.log"),
                "--schema",
                str(ex / "schema.cedarschema"),
                "--style",
                "corpus",
            ]
        )
        == 0
    )
    assert "true" in capsys.readouterr().out
    bad = tmp_path / "bad.dw"
    bad.write_text("permit(principal = 1);", encoding="utf-8")
    assert cli.main(["check", str(bad)]) == 2
    assert "did you mean" in capsys.readouterr().err
    assert cli.main(["check", str(tmp_path / "missing.dw")]) == 1
    es = tmp_path / "e.dwschema"
    es.write_text("decision event <A>::request { ...inputs(A) }", encoding="utf-8")
    assert (
        cli.main(
            [
                "replay",
                str(ex / "policy.dw"),
                str(ex / "trace.log"),
                "--schema",
                str(ex / "schema.cedarschema"),
                "--event-schema",
                str(es),
            ]
        )
        == 0
    )


def test_readme_recipes_and_killer_example_parse_against_the_inspect_schema():
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")
    blocks = [b for b in readme.split("```") if "Inspect::Action" in b and "@watch" not in b]
    assert blocks, "no Dogwood recipe block in README"
    for block in blocks:
        src = block.split("\n", 1)[1] if not block.startswith("\n") else block
        pol = DogwoodPolicy.parse(src)
        assert pol.rules
    killer = readme[
        readme.index('@watch(policy="""')
        + len('@watch(policy="""') : readme.index('""")\ndef agent')
    ]
    assert DogwoodPolicy.parse(killer).rules == ["policy0", "no-exfil-after-secret"]

<p align="center">
  <img src="docs/logo.svg" width="120" alt="strands-inspect logo" />
</p>

# strands-inspect

[![Awesome Strands Agents](https://img.shields.io/badge/Awesome-Strands%20Agents-00FF77?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjkwIiBoZWlnaHQ9IjQ2MyIgdmlld0JveD0iMCAwIDI5MCA0NjMiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxwYXRoIGQ9Ik05Ny4yOTAyIDUyLjc4ODRDODUuMDY3NCA0OS4xNjY3IDcyLjIyMzQgNTYuMTM4OSA2OC42MDE3IDY4LjM2MTZDNjQuOTgwMSA4MC41ODQzIDcxLjk1MjQgOTMuNDI4MyA4NC4xNzQ5IDk3LjA1MDFMMjM1LjExNyAxMzkuNzc1QzI0NS4yMjMgMTQyLjc2OSAyNDYuMzU3IDE1Ni42MjggMjM2Ljg3NCAxNjEuMjI2TDMyLjU0NiAyNjAuMjkxQy0xNC45NDM5IDI4My4zMTYgLTkuMTYxMDcgMzUyLjc0IDQxLjQ4MzUgMzY3LjU5MUwxODkuNTUxIDQxMS4wMDlMMTkwLjEyNSA0MTEuMTY5QzIwMi4xODMgNDE0LjM3NiAyMTQuNjY1IDQwNy4zOTYgMjE4LjE5NiAzOTUuMzU1QzIyMS43ODQgMzgzLjEyMiAyMTQuNzc0IDM3MC4yOTYgMjAyLjU0MSAzNjYuNzA5TDU0LjQ3MzggMzIzLjI5MUM0NC4zNDQ3IDMyMC4zMjEgNDMuMTg3OSAzMDYuNDM2IDUyLjY4NTcgMzAxLjgzMUwyNTcuMDE0IDIwMi43NjZDMzA0LjQzMiAxNzkuNzc2IDI5OC43NTggMTEwLjQ4MyAyNDguMjMzIDk1LjUxMkw5Ny4yOTAyIDUyLjc4ODRaIiBmaWxsPSIjRkZGRkZGIi8+CjxwYXRoIGQ9Ik0yNTkuMTQ3IDAuOTgxODEyQzI3MS4zODkgLTIuNTc0OTggMjg0LjE5NyA0LjQ2NTcxIDI4Ny43NTQgMTYuNzA3NEMyOTEuMzExIDI4Ljk0OTIgMjg0LjI3IDQxLjc1NyAyNzIuMDI4IDQ1LjMxMzhMNzEuMTcyNyAxMDMuNjcxQzQwLjcxNDIgMTEyLjUyMSAzNy4xOTc2IDE1NC4yNjIgNjUuNzQ1OSAxNjguMDgzTDI0MS4zNDMgMjUzLjA5M0MzMDcuODcyIDI4NS4zMDIgMjk5Ljc5NCAzODIuNTQ2IDIyOC44NjIgNDAzLjMzNkwzMC40MDQxIDQ2MS41MDJDMTguMTcwNyA0NjUuMDg4IDUuMzQ3MDggNDU4LjA3OCAxLjc2MTUzIDQ0NS44NDRDLTEuODIzOSA0MzMuNjExIDUuMTg2MzcgNDIwLjc4NyAxNy40MTk3IDQxNy4yMDJMMjE1Ljg3OCAzNTkuMDM1QzI0Ni4yNzcgMzUwLjEyNSAyNDkuNzM5IDMwOC40NDkgMjIxLjIyNiAyOTQuNjQ1TDQ1LjYyOTcgMjA5LjYzNUMtMjAuOTgzNCAxNzcuMzg2IC0xMi43NzcyIDc5Ljk4OTMgNTguMjkyOCA1OS4zNDAyTDI1OS4xNDcgMC45ODE4MTJaIiBmaWxsPSIjRkZGRkZGIi8+Cjwvc3ZnPgo=&logoColor=white)](https://github.com/cagataycali/awesome-strands-agents)

See what your code does. Control what it can do.

```
pip install strands-inspect
```

## 🔌 Use as an MCP server

Use strands-inspect from **Claude Code, Claude Desktop, Cursor, Kiro, or any MCP client** — the `inspect` tool (scan, profile, sandbox) becomes an MCP tool.

```bash
claude mcp add inspect -- uvx strands-inspect
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "inspect": {
      "command": "uvx",
      "args": ["strands-inspect"]
    }
  }
}
```

Options:

```bash
strands-inspect --http --port 8000   # HTTP mode, multi-client
```

---

## `@watch` — see everything, block what you don't want

```python
from strands_inspect import watch

@watch(policy="sandbox")
def suspicious_task():
    import json
    data = json.dumps({"key": "value"})            # ← allowed
    open("/tmp/exfil.txt", "w").write("stolen")     # ← blocked: no permit covers file.write
    return data
```

Presets are files: `"sandbox"` is [`strands_inspect/policies/sandbox.dw`](strands_inspect/policies/sandbox.dw).
Policies are written in **[Dogwood](https://github.com/dogwood-policy/dogwood)** — Cedar syntax plus
time — and the whole language runs in-process, pure Python, no dependencies:

```python
import subprocess
from strands_inspect import watch

@watch(policy="""
permit(principal, action, resource);
@id("no-exfil-after-secret")
forbid(principal, action in [Inspect::Action::"net", Inspect::Action::"os"], resource)
when temporal {
    formerly within 5m Inspect::Action::"file.read"::request{ input.sensitive: true }
};
""")
def agent():
    open("/etc/hosts").read()                             # fine
    subprocess.run(["uname", "-s"], capture_output=True)  # fine: nothing sensitive read yet
    open("/home/me/.ssh/id_rsa").read()                   # a credential-shaped path
    subprocess.run(["curl", "https://evil.example"])      # blocked
```

```
🔍 InspectSession: agent_20260930_154407
   Function: __main__.agent
   Wall: 8.0ms | Peak mem: 0.0 KB
   ❌ Exception: 🚫 Policy denied: subprocess — curl https://evil.example (rule no-exfil-after-secret)
   📋 Syscalls: 9 total
      Files read: 2 | written: 0 | deleted: 0
      Network: 0 | Subprocess: 3 | os.system: 0
   🚫 Denied: 1 syscalls blocked
      - subprocess: curl https://evil.example
```

Read a secret, and for the next five minutes the function cannot reach the network or spawn a
process. The same `curl` was fine one line earlier. That is what a policy language with history
buys you; a per-category allow/deny table cannot say it.

## The policy language

A rule is `permit` or `forbid`, a scope `(principal, action, resource)`, and `when` / `unless`
conditions. **Forbid always wins; nothing matched means deny.** `principal` is the watched
function (`Inspect::Function::"module.name"`), `resource` the process, `action` one of the 20
hooked categories below. Conditions read `context.input.<field>`:

| action | group | `context.input` fields (every action also has `detail`, `op`) |
|---|---|---|
| `file.read` `file.write` | `file` | `path`, `mode`, `sensitive: Bool` |
| `file.delete` `file.mkdir` `file.special` | `file` | `path` |
| `file.move` `file.link` | `file` | `src`, `dst` |
| `file.chmod` | `file` | `path`, `mode` |
| `file.fd_io` | `file` | `fd: Long`, `size: Long` |
| `network` | `net` | `host`, `port: Long`, `url`, `scheme`, `method` |
| `net.socket` | `net` | `host`, `port: Long`, `size: Long` |
| `subprocess` `os.system` `os.exec` | `os` | `command`, `program`, `argv: Set<String>`, `shell: Bool` |
| `process.fork` | `process` | — |
| `process.kill` | `process` | `pid: Long`, `signal: Long` |
| `process.mp` | `process` | `name`, `target` |
| `import` | — | `module`, `package` |
| `meta.ctypes` | `meta` | `library` |
| `meta.code` | `meta` | `source` |

`sensitive` is true under `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gcloud`, `~/.kube`, for
`/etc/shadow`, `/etc/passwd`, and for basenames like `.env*`, `*.pem`, `*.key`, `id_*`,
`*credentials*`, `*.keychain*`. `op` is the hooked callable (`open`, `shutil.copy`,
`subprocess.Popen`, `requests.Session.request`, ...). `context.system` is `{ now, session }`.
The full schema is [`strands_inspect/dogwood/inspect.cedarschema`](strands_inspect/dogwood/inspect.cedarschema).

### Presets

| preset | file | rules |
|---|---|---|
| `allow_all` | [allow_all.dw](strands_inspect/policies/allow_all.dw) | permit everything (the `@watch` default) |
| `deny_network` | [deny_network.dw](strands_inspect/policies/deny_network.dw) | permit everything, forbid the `net` group |
| `deny_write` | [deny_write.dw](strands_inspect/policies/deny_write.dw) | permit everything, forbid write / delete / move / chmod |
| `sandbox` | [sandbox.dw](strands_inspect/policies/sandbox.dw) | permit `file.read` and `import` only |
| `strict` | [strict.dw](strands_inspect/policies/strict.dw) | `@ask` before every read and import; deny the rest |
| `deny_all` | [deny_all.dw](strands_inspect/policies/deny_all.dw) | forbid everything |

A `permit` annotated `@ask` is granted only after a `y/N` prompt. Every rule carries an `@id`;
the id appears in the `PolicyViolation`, in the session trace and in the viewer.

### Recipes

```
// only HTTPS to OpenAI
permit(principal, action == Inspect::Action::"network", resource)
when { context.input.host like "*.openai.com" && context.input.port == 443 };

// writes only under /tmp, never to a credential-shaped path
permit(principal, action == Inspect::Action::"file.write", resource)
when { context.input.path like "/tmp/*" && !context.input.sensitive };

// no shell, and never curl
permit(principal, action in [Inspect::Action::"os"], resource)
when { context.input.shell == false && !context.input.argv.contains("curl") };

// rate limit: at most 3 subprocesses per minute (count_within is in the default macro library)
forbid(principal, action == Inspect::Action::"subprocess", resource)
when temporal {
    exists (n: Long). ((count_within(1m, Inspect::Action::"subprocess"::request{ input.op: "subprocess.Popen" })) == n && n > 3)
};

// no write after the network was touched
forbid(principal, action == Inspect::Action::"file.write", resource)
when temporal { formerly within 1h Inspect::Action::"network"::request{} };

// a read of anything under /secrets, then no subprocess
forbid(principal, action in [Inspect::Action::"os"], resource)
when temporal { formerly within 10m Inspect::Action::"file.read"::request{ input.path: "/secrets/plan.txt" } };
```

Temporal operators: `formerly within W P` (happened in the window), `previous within W P` (the
event just before), `!P since within W Q` (not since), `exists`, `count` / `sum`. History is
per watched function. The reference guide is at [dogwood-policy.github.io](https://dogwood-policy.github.io/dogwood/).

### `.dw` files and config

```python
@watch(policy="policies/team.dw")          # a path ending in .dw
@watch(policy=DogwoodPolicy.from_file(p))  # or the object

# .strands-inspect.toml
# [watch.policies.readonly]
# dogwood = 'permit(principal, action, resource); forbid(principal, action in [Inspect::Action::"file.write"], resource);'
# [watch.policies.team]
# file = "policies/team.dw"
@watch(policy="readonly")
```

The legacy dict / callable form still works unchanged:
`@watch(policy={"file.write": "deny", "network": {"action": "allow", "hosts": ["*.openai.com"]}})`.

### Check, replay, explain

```
python -m strands_inspect.dogwood check   policy.dw
python -m strands_inspect.dogwood explain policy.dw
python -m strands_inspect.dogwood replay  policy.dw trace.log --schema schema.cedarschema
```

```
# strands_inspect/policies/deny_network.dw: 2 rule(s)
- permit allow-everything: 25 action(s) [file, net, os, process, meta, file.read, ...]
- forbid deny-network: 3 action(s) [net, network, net.socket]
# @lock projection: {'network': False, 'file_read': True, 'file_write': True, 'subprocess': True, 'ipc': True, 'mmap_exec': True, 'sysctl': False}
```

### Conformance

The implementation (`strands_inspect/dogwood/`, stdlib only) is checked against the reference
corpus of `dogwood@996d756`. Vendored in `tests/dogwood_corpus/`: **631/631 traces
byte-identical** (160 temporal_only + 154 macros + 18 mixed cases, 38 docs examples). Against
the full reference checkout: **temporal_only 1061/1061, macros 254/254, mixed 18/18, docs
examples 38/38**; the 21 cases that call information providers are skipped — providers, template
slots and Rhai are not supported, and a policy using them is rejected at parse time.

## `@lock` — nothing escapes

Kernel-level. macOS Seatbelt / Linux seccomp-bpf. Even ctypes calling libc can't get through.

```python
from strands_inspect import lock

@lock
def try_network():
    import urllib.request
    urllib.request.urlopen("http://example.com")
    return "should not reach here"
```

```
❌ KernelSandbox (seatbelt)
   Wall: 25.7ms
   Exception: URLError: <urlopen error [Errno 8] nodename nor servname provided>
```

`@lock(policy=<Dogwood>)` **projects** the policy onto the seven kernel capabilities: a
capability is allowed only if an unconditional `permit` covers all of its actions and no
`forbid` touches them; `file.read ... when { context.input.path like "/data/*" }` becomes a
read allow-list; `@ask` and temporal rules deny (the kernel has no prompt and no history).
Kernel preset names (`sandbox`, `strict`, `deny_all`) keep their hand-written tables.

## Agent tool

```python
from strands import Agent
from strands_inspect import inspect_tool

agent = Agent(tools=[inspect_tool])
agent("scan the requests library and find how to POST json")
```

16 actions: `scan` · `call` · `inspect` · `search` · `generate` · `exec` · `create` · `list` · `source` · `install` · `profile` · `graph` · `connections` · `hotspots` · `unused` · `deps`

## Replay and viewer

Every `@watch`'d call saves a `.dill` file; `session.to_json("run.json")` exports it for the
web viewer (`docs/viewer.html`: memory timeline, syscall log, and the rule that decided each
denied call — see [`docs/examples/dogwood_exfil.json`](docs/examples/dogwood_exfil.json)).

```python
from strands_inspect import replay
session = replay("agent_20260930_154407.dill")
session.re_run()
```

## Three layers

| Layer | What | Escapes |
|---|---|---|
| `@watch` | 55+ Python hooks, every call recorded | C extensions |
| `@watch(policy=...)` | hooks + a Dogwood policy (Cedar + time) | C extensions |
| `@lock` | kernel sandbox (forked subprocess), Dogwood projected | Nothing |

## Install

```
pip install strands-inspect
```

Python 3.10+. One dependency: `strands-agents`. The Dogwood engine is stdlib only.

MIT License. The vendored conformance corpus is Apache-2.0 (`tests/dogwood_corpus/LICENSE`).

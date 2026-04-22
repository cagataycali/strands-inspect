<p align="center">
  <img src="docs/logo.svg" width="120" alt="strands-inspect logo" />
</p>

# strands-inspect

[![Awesome Strands Agents](https://img.shields.io/badge/Awesome-Strands%20Agents-00FF77?style=flat-square&logo=data:image/svg+xml;base64,PHN2ZyB3aWR0aD0iMjkwIiBoZWlnaHQ9IjQ2MyIgdmlld0JveD0iMCAwIDI5MCA0NjMiIGZpbGw9Im5vbmUiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyI+CjxwYXRoIGQ9Ik05Ny4yOTAyIDUyLjc4ODRDODUuMDY3NCA0OS4xNjY3IDcyLjIyMzQgNTYuMTM4OSA2OC42MDE3IDY4LjM2MTZDNjQuOTgwMSA4MC41ODQzIDcxLjk1MjQgOTMuNDI4MyA4NC4xNzQ5IDk3LjA1MDFMMjM1LjExNyAxMzkuNzc1QzI0NS4yMjMgMTQyLjc2OSAyNDYuMzU3IDE1Ni42MjggMjM2Ljg3NCAxNjEuMjI2TDMyLjU0NiAyNjAuMjkxQy0xNC45NDM5IDI4My4zMTYgLTkuMTYxMDcgMzUyLjc0IDQxLjQ4MzUgMzY3LjU5MUwxODkuNTUxIDQxMS4wMDlMMTkwLjEyNSA0MTEuMTY5QzIwMi4xODMgNDE0LjM3NiAyMTQuNjY1IDQwNy4zOTYgMjE4LjE5NiAzOTUuMzU1QzIyMS43ODQgMzgzLjEyMiAyMTQuNzc0IDM3MC4yOTYgMjAyLjU0MSAzNjYuNzA5TDU0LjQ3MzggMzIzLjI5MUM0NC4zNDQ3IDMyMC4zMjEgNDMuMTg3OSAzMDYuNDM2IDUyLjY4NTcgMzAxLjgzMUwyNTcuMDE0IDIwMi43NjZDMzA0LjQzMiAxNzkuNzc2IDI5OC43NTggMTEwLjQ4MyAyNDguMjMzIDk1LjUxMkw5Ny4yOTAyIDUyLjc4ODRaIiBmaWxsPSIjRkZGRkZGIi8+CjxwYXRoIGQ9Ik0yNTkuMTQ3IDAuOTgxODEyQzI3MS4zODkgLTIuNTc0OTggMjg0LjE5NyA0LjQ2NTcxIDI4Ny43NTQgMTYuNzA3NEMyOTEuMzExIDI4Ljk0OTIgMjg0LjI3IDQxLjc1NyAyNzIuMDI4IDQ1LjMxMzhMNzEuMTcyNyAxMDMuNjcxQzQwLjcxNDIgMTEyLjUyMSAzNy4xOTc2IDE1NC4yNjIgNjUuNzQ1OSAxNjguMDgzTDI0MS4zNDMgMjUzLjA5M0MzMDcuODcyIDI4NS4zMDIgMjk5Ljc5NCAzODIuNTQ2IDIyOC44NjIgNDAzLjMzNkwzMC40MDQxIDQ2MS41MDJDMTguMTcwNyA0NjUuMDg4IDUuMzQ3MDggNDU4LjA3OCAxLjc2MTUzIDQ0NS44NDRDLTEuODIzOSA0MzMuNjExIDUuMTg2MzcgNDIwLjc4NyAxNy40MTk3IDQxNy4yMDJMMjE1Ljg3OCAzNTkuMDM1QzI0Ni4yNzcgMzUwLjEyNSAyNDkuNzM5IDMwOC40NDkgMjIxLjIyNiAyOTQuNjQ1TDQ1LjYyOTcgMjA5LjYzNUMtMjAuOTgzNCAxNzcuMzg2IC0xMi43NzcyIDc5Ljk4OTMgNTguMjkyOCA1OS4zNDAyTDI1OS4xNDcgMC45ODE4MTJaIiBmaWxsPSIjRkZGRkZGIi8+Cjwvc3ZnPgo=&logoColor=white)](https://github.com/cagataycali/awesome-strands-agents)

See what your code does. Control what it can do.

```
pip install strands-inspect
```

## `@watch` — see everything

```python
from strands_inspect import watch

@watch
def fibonacci(n):
    memo = {}
    def fib(k):
        if k <= 1: return k
        if k not in memo: memo[k] = fib(k-1) + fib(k-2)
        return memo[k]
    return fib(n)

result = fibonacci(80)
```

```
🔍 InspectSession: fibonacci_20260302_060222
   Function: __main__.fibonacci
   Wall: 0.1ms | Peak mem: 8.0 KB
   Return: 23416728348467685
```

Add a policy to block what you don't want:

```python
from strands_inspect import watch, PolicyViolation

@watch(policy="sandbox")
def suspicious_task():
    import json
    data = json.dumps({"key": "value"})  # ← allowed

    try:
        open("/tmp/exfil.txt", "w").write("stolen data")  # ← blocked
    except PolicyViolation as e:
        print(f"CAUGHT: {e}")

    try:
        import subprocess
        subprocess.run(["curl", "http://evil.com"])  # ← blocked
    except PolicyViolation as e:
        print(f"CAUGHT: {e}")

    return data
```

```
🔍 InspectSession: suspicious_task_20260302_060244
   Wall: 0.1ms | Peak mem: 7.0 KB
   Return: '{"key": "value"}'
   🚫 Denied: 2 syscalls blocked
      - file.write: /tmp/exfil.txt (mode=w)
      - subprocess: curl http://evil.com
```

## `@lock` — nothing escapes

Kernel-level. macOS Seatbelt / Linux seccomp-bpf. Even ctypes calling libc can't get through.

```python
from strands_inspect import lock

@lock
def try_network():
    import urllib.request
    urllib.request.urlopen("http://example.com")
    return "should not reach here"

try:
    result = try_network()
except RuntimeError as e:
    print(f"Blocked: {e}")
```

```
❌ KernelSandbox (seatbelt)
   Wall: 25.7ms
   Exception: URLError: <urlopen error [Errno 8] nodename nor servname provided>
```

## Granular policies

```python
@watch(policy={
    "file.read": {"action": "allow", "paths": ["/tmp/**"]},
    "file.write": "deny",
    "network": {"action": "allow", "hosts": ["*.openai.com"]},
    "subprocess": "deny",
    "import": "log",
})
def guarded():
    ...
```

| Preset | Does |
|---|---|
| `"allow_all"` | Log everything, block nothing |
| `"deny_network"` | Block all network |
| `"deny_write"` | Block file writes and deletes |
| `"sandbox"` | Block writes, network, subprocess, exec |
| `"strict"` | Block almost everything |
| `"deny_all"` | Block everything |

20 categories: `file.read` · `file.write` · `file.delete` · `file.move` · `file.chmod` · `file.link` · `file.mkdir` · `file.fd_io` · `file.special` · `network` · `net.socket` · `subprocess` · `os.system` · `os.exec` · `process.fork` · `process.kill` · `process.mp` · `import` · `meta.ctypes` · `meta.code`

## Agent tool

```python
from strands import Agent
from strands_inspect import inspect_tool

agent = Agent(tools=[inspect_tool])
agent("scan the requests library and find how to POST json")
```

```
📦 requests — Version: 2.32.3
📊 12 modules, 184 callables

  - post(url, data=None, json=None, **kwargs) — Sends a POST request
  - get(url, params=None, **kwargs) — Sends a GET request
  ...
```

16 actions: `scan` · `call` · `inspect` · `search` · `generate` · `exec` · `create` · `list` · `source` · `install` · `profile` · `graph` · `connections` · `hotspots` · `unused` · `deps`

## Replay

Every `@watch`'d call saves a `.dill` file:

```python
from strands_inspect import replay

session = replay("fibonacci_20260302_060222.dill")
session.re_run()        # same args
session.re_run(100)     # different args
```

## Viewer

Export JSON. Drop into the web viewer. Memory timeline, CPU flamegraph, syscall log.

```python
session.to_json("profile.json")
# Open docs/index.html → viewer tab
```

## Three layers

| Layer | What | Escapes |
|---|---|---|
| `@watch` | 55+ Python hooks | C extensions |
| `@watch(policy=...)` | hooks + allow/deny | C extensions |
| `@lock` | Kernel sandbox (forked subprocess) | Nothing |

## Install

```
pip install strands-inspect
```

Python 3.10+. One dependency: `strands-agents`. Everything else is stdlib.

MIT License.

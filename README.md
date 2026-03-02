<p align="center">
  <img src="docs/logo.svg" width="120" alt="strands-inspect logo" />
</p>

# strands-inspect

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

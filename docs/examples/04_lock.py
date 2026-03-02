"""@lock — kernel-level sandbox. Nothing escapes."""
from strands_inspect import lock

@lock
def try_network():
    import urllib.request
    urllib.request.urlopen("http://example.com")
    return "should not reach here"

try:
    result = try_network()
except RuntimeError as e:
    print(f"Kernel blocked it: {e}")

# Direct API for more control
from strands_inspect import KernelSandbox

sb = KernelSandbox(policy={"network": False, "file_write": False})
result = sb.run(lambda: open("/tmp/test", "w").write("data"))
print(f"\nSuccess: {result.success}")
print(f"Killed: {result.killed_by_sandbox}")
print(f"Violations: {result.violations}")

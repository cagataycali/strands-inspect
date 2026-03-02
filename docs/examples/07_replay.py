"""Session replay — re-run, diff, export."""
from strands_inspect import watch, replay, list_sessions
import os

@watch(dump=True, print_summary=False)
def compute(x, y):
    return x ** y

# Run twice with different args
compute(2, 10)
path1 = compute.__last_dump__

compute(2, 20)
path2 = compute.__last_dump__

# Replay from disk
s1 = replay(path1)
s2 = replay(path2)
print(f"Run 1: {s1.return_value} ({s1.wall_time_ms:.2f}ms)")
print(f"Run 2: {s2.return_value} ({s2.wall_time_ms:.2f}ms)")

# Diff two runs
diff = s1.diff(s2)
print(f"\nTime delta: {diff['wall_time_delta_ms']:.2f}ms")
print(f"Return changed: {diff['return_changed']}")

# Export as JSON for the web viewer
s2.to_json("/tmp/compute_profile.json")
print(f"\nExported to /tmp/compute_profile.json")

# List all sessions
for s in list_sessions()[:3]:
    print(f"  {s['name']} ({s['size_kb']:.0f} KB)")

# Cleanup
os.unlink(path1)
os.unlink(path2)

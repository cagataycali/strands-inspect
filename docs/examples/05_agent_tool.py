"""inspect_tool — give any Strands agent package superpowers."""
from strands_inspect import inspect_tool

# Scan a package
result = inspect_tool(action="scan", target="json", depth=1)
print(result["content"][0]["text"][:500])

print("\n" + "=" * 50)

# Call a function by dotted path
result = inspect_tool(
    action="call",
    target="json.dumps",
    args='[{"hello": "world"}]',
    kwargs='{"indent": 2}',
)
print(result["content"][0]["text"])

print("\n" + "=" * 50)

# Search across a package
result = inspect_tool(action="search", target="json", query="encode string")
print(result["content"][0]["text"][:400])

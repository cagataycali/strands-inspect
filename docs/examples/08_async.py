"""@watch works with async functions — zero changes needed."""
import asyncio
from strands_inspect import watch

@watch(dump=False)
async def fetch_and_process(url):
    await asyncio.sleep(0.05)  # simulate I/O
    return f"processed {url}"

@watch(policy="sandbox", dump=False)
async def async_sandbox():
    await asyncio.sleep(0.01)
    import json
    return json.dumps({"async": True})

async def main():
    r1 = await fetch_and_process("https://example.com")
    print(f"Result: {r1}")

    r2 = await async_sandbox()
    print(f"Sandboxed: {r2}")

asyncio.run(main())

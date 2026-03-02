"""Profile code — memory timeline, CPU flamegraph, allocations."""
from strands_inspect import inspect_tool

result = inspect_tool(action="profile", code="""
import math

def sieve(n):
    is_prime = [True] * (n + 1)
    is_prime[0] = is_prime[1] = False
    for i in range(2, int(math.sqrt(n)) + 1):
        if is_prime[i]:
            for j in range(i * i, n + 1, i):
                is_prime[j] = False
    return [i for i in range(n + 1) if is_prime[i]]

primes = sieve(50000)
len(primes)
""")
print(result["content"][0]["text"][:1200])

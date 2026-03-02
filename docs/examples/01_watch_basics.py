"""@watch — see everything a function does."""
from strands_inspect import watch

@watch
def fibonacci(n):
    """Recursive fibonacci with memoization."""
    memo = {}
    def fib(k):
        if k <= 1:
            return k
        if k not in memo:
            memo[k] = fib(k - 1) + fib(k - 2)
        return memo[k]
    return fib(n)

result = fibonacci(80)
print(f"fib(80) = {result}")

# Access the session
session = fibonacci.__last_session__
print(f"\nWall time: {session.wall_time_ms:.1f}ms")
print(f"Peak memory: {session.memory_peak_kb:.1f} KB")
print(f"Syscalls: {len(session.syscalls)}")

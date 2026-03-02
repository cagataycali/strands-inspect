"""Tests for async @watch support."""

import asyncio
import inspect
import pytest
from strands_inspect import watch, PolicyViolation


class TestAsyncWatch:
    def test_async_basic(self):
        @watch(dump=False, print_summary=False)
        async def async_add(a, b):
            await asyncio.sleep(0.001)
            return a + b

        result = asyncio.run(async_add(3, 4))
        assert result == 7
        assert async_add.__last_session__ is not None
        assert async_add.__last_session__.return_value == 7

    def test_async_with_policy(self):
        @watch(policy="sandbox", dump=False, print_summary=False)
        async def async_blocked():
            await asyncio.sleep(0.001)
            try:
                open("/tmp/test_async_write", "w")
            except PolicyViolation:
                return "blocked"
            return "allowed"

        result = asyncio.run(async_blocked())
        assert result == "blocked"
        session = async_blocked.__last_session__
        assert len(session.denied) > 0

    def test_async_exception(self):
        @watch(dump=False, print_summary=False)
        async def async_fail():
            await asyncio.sleep(0.001)
            raise ValueError("test error")

        result = asyncio.run(async_fail())
        assert result is None
        assert "ValueError" in async_fail.__last_session__.exception

    def test_sync_still_works(self):
        @watch(dump=False, print_summary=False)
        def sync_add(a, b):
            return a + b

        result = sync_add(5, 6)
        assert result == 11
        assert not inspect.iscoroutinefunction(sync_add)

    def test_async_is_coroutine(self):
        @watch(dump=False, print_summary=False)
        async def my_coro():
            return 42

        assert inspect.iscoroutinefunction(my_coro)
        result = asyncio.run(my_coro())
        assert result == 42

"""Shared fixtures for strands-inspect tests."""

import os
import tempfile
import pytest


@pytest.fixture
def tmp_file():
    """Create a temporary file with content, cleanup after test."""
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".txt", dir="/tmp")
    tf.write(b"hello world")
    tf.close()
    yield tf.name
    try:
        os.unlink(tf.name)
    except FileNotFoundError:
        pass


@pytest.fixture
def tmp_dir():
    """Create a temporary directory, cleanup after test."""
    d = tempfile.mkdtemp(dir="/tmp", prefix="inspect_test_")
    yield d
    import shutil

    try:
        shutil.rmtree(d)
    except FileNotFoundError:
        pass

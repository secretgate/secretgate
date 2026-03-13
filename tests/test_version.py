"""Test version consistency between __init__.py and pyproject.toml."""

from pathlib import Path

import secretgate


def test_version_matches_pyproject():
    """__init__.py version should match pyproject.toml."""
    pyproject = Path(__file__).parent.parent / "pyproject.toml"
    content = pyproject.read_text()
    # Extract version from pyproject.toml
    for line in content.splitlines():
        if line.strip().startswith("version"):
            pyproject_version = line.split("=", 1)[1].strip().strip('"')
            break
    else:
        raise AssertionError("version not found in pyproject.toml")
    assert secretgate.__version__ == pyproject_version


def test_version_is_semver():
    """Version should look like a semantic version."""
    parts = secretgate.__version__.split(".")
    assert len(parts) >= 2
    assert all(p.isdigit() for p in parts[:3] if p)

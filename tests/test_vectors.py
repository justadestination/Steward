"""The shared vectors must hold for the Python engine. pwa/test/ checks the JS one."""

import json

import pytest

from steward.vectors import files, rejected, run


@pytest.mark.parametrize("path", files(), ids=lambda p: p.stem)
def test_vector(path, catalog):
    vector = json.loads(path.read_text(encoding="utf-8"))
    if "rejects" in vector:
        assert rejected(vector, catalog) == []
    else:
        assert vector["expected"], "run `python3 -m steward vectors --write` and review"
        assert run(vector, catalog) == vector["expected"]

from scripter.intel.vuln_db import load_signatures
from scripter.validation.checks import CHECKS


def test_bundled_signatures_load_without_error():
    sigs = load_signatures()
    assert len(sigs) >= 9
    ids = [s.id for s in sigs]
    assert len(ids) == len(set(ids))


def test_checks_referenced_in_signatures_are_registered():
    for sig in load_signatures():
        if sig.check:
            assert sig.check in CHECKS, f"{sig.id} references unregistered check {sig.check!r}"


def test_confidence_values_are_in_range():
    for sig in load_signatures():
        assert 0.0 <= sig.confidence_base <= 1.0

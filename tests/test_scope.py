import pytest

from scripter.scope import ScopeError, parse_scope, require_in_scope


def test_empty_scope_rejected():
    with pytest.raises(ScopeError):
        parse_scope([])


def test_single_host():
    scope = parse_scope(["10.10.1.5"])
    assert scope.hosts == ("10.10.1.5",)


def test_cidr_expands_to_usable_hosts():
    scope = parse_scope(["10.10.1.0/30"])
    assert set(scope.hosts) == {"10.10.1.1", "10.10.1.2"}


def test_public_address_rejected_by_default():
    with pytest.raises(ScopeError):
        parse_scope(["8.8.8.8"])


def test_public_address_allowed_when_flagged():
    scope = parse_scope(["8.8.8.8"], allow_public=True)
    assert scope.hosts == ("8.8.8.8",)


def test_loopback_allowed_by_default():
    scope = parse_scope(["127.0.0.1"])
    assert scope.hosts == ("127.0.0.1",)


def test_malformed_entry_rejected():
    with pytest.raises(ScopeError):
        parse_scope(["not-an-ip!!"])


def test_max_hosts_safety_valve():
    with pytest.raises(ScopeError):
        parse_scope(["10.0.0.0/8"], max_hosts=10)


def test_require_in_scope_rejects_outside_host():
    scope = parse_scope(["10.10.1.5"])
    with pytest.raises(ScopeError):
        require_in_scope("10.10.1.6", scope)
    require_in_scope("10.10.1.5", scope)  # must not raise

import pytest

from scripter.redteam import registry
from scripter.redteam.models import RiskLevel, ToolCapability, ToolDefinition


@pytest.fixture(autouse=True)
def _clean_registry():
    registry.reset_for_tests()
    yield
    registry.reset_for_tests()


def _definition(name: str = "x") -> ToolDefinition:
    return ToolDefinition(
        name=name, description="d", protocols=(), required_inputs=(), capability=ToolCapability.PASSIVE_PROBE,
        risk=RiskLevel.PASSIVE, requires_network=False,
    )


def test_duplicate_tool_registration_is_rejected():
    registry.register_tool(_definition("dup"))
    with pytest.raises(registry.RegistryError):
        registry.register_tool(_definition("dup"))


def test_get_unknown_tool_raises():
    with pytest.raises(registry.RegistryError):
        registry.get_tool("does-not-exist")


def test_builtin_tools_register_without_duplicate_ids():
    registry.ensure_builtin_tools_registered()
    names = [t.name for t in registry.list_tools()]
    assert len(names) == len(set(names))
    assert "http_audit" in names
    assert "simulate" in names


def test_ensure_builtin_tools_registered_is_idempotent():
    registry.ensure_builtin_tools_registered()
    first_count = len(registry.list_tools())
    registry.ensure_builtin_tools_registered()
    assert len(registry.list_tools()) == first_count


def test_list_tools_is_sorted_by_name():
    registry.ensure_builtin_tools_registered()
    names = [t.name for t in registry.list_tools()]
    assert names == sorted(names)

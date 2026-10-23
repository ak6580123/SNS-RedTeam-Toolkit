"""Central registry of red-team tools.

Deliberately dumb and static: a tool is a name -> ToolDefinition mapping
populated once by redteam.tools.register_builtin_tools(). This module
never imports redteam.tools at module load time (avoids an import cycle,
since every tool module imports registry to register itself) and never
loads arbitrary Python modules, executes user-supplied code, or resolves
a shell command from configuration.
"""
from __future__ import annotations

from scripter.redteam.models import ToolDefinition

_REGISTRY: dict[str, ToolDefinition] = {}


class RegistryError(ValueError):
    pass


def register_tool(definition: ToolDefinition) -> None:
    if definition.name in _REGISTRY:
        raise RegistryError(f"duplicate tool id: {definition.name!r}")
    _REGISTRY[definition.name] = definition


def get_tool(name: str) -> ToolDefinition:
    try:
        return _REGISTRY[name]
    except KeyError:
        raise RegistryError(f"unknown tool: {name!r}") from None


def list_tools() -> list[ToolDefinition]:
    return sorted(_REGISTRY.values(), key=lambda t: t.name)


def is_registered(name: str) -> bool:
    return name in _REGISTRY


def reset_for_tests() -> None:
    """Test-only: clear the registry so duplicate-registration tests start
    from a clean slate instead of colliding with the builtin tool set."""
    _REGISTRY.clear()


def ensure_builtin_tools_registered() -> None:
    """Idempotent: safe to call from every CLI command / TUI action. The
    bundled tool set is only ever registered once per process - a second
    call is a no-op, so it can never raise RegistryError on repeated use."""
    if _REGISTRY:
        return
    from scripter.redteam.tools import register_builtin_tools

    register_builtin_tools()

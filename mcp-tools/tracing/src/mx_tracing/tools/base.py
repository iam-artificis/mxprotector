"""ITool ABC + decorator-based registry (OCP).

Every MCP tool is a single file under ``mx_tracing.tools`` that
declares one ``ITool`` subclass decorated with ``@register_tool``.
The registry is populated at import time; ``server.py`` imports
``mx_tracing.tools`` to trigger registration.

Adding a new tool = new file, zero edits to existing ones.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Generic, TypeVar

from pydantic import BaseModel

if TYPE_CHECKING:
    from mx_tracing.session import Session


InputT = TypeVar("InputT", bound=BaseModel)
OutputT = TypeVar("OutputT", bound=BaseModel)


class ITool(ABC, Generic[InputT, OutputT]):
    """Contract for a single MCP tool.

    Subclasses declare the following class-level attributes:
        name:          MCP-visible tool identifier.
        description:   Short human-readable summary (one-liner).
        input_schema:  pydantic model for the tool's arguments.
        output_schema: pydantic model for the tool's return value.

    And implement ``run(args, session) -> output``.
    """

    name: ClassVar[str]
    description: ClassVar[str]
    input_schema: ClassVar[type[BaseModel]]
    output_schema: ClassVar[type[BaseModel]]

    @abstractmethod
    async def run(self, args: InputT, session: "Session") -> OutputT:
        """Execute the tool. Must return an instance of output_schema."""


_REGISTRY: list[type[ITool]] = []


def register_tool(cls: type[ITool]) -> type[ITool]:
    """Class decorator: register a tool at import time.

    Validates the contract (required class attrs, unique name) so that
    misconfigured tools fail fast at module load, not on first call.
    """
    if not issubclass(cls, ITool):
        raise TypeError(f"{cls.__name__} must subclass ITool")

    for required in ("name", "description", "input_schema", "output_schema"):
        if not hasattr(cls, required):
            raise TypeError(
                f"{cls.__name__} missing required class attr '{required}'"
            )

    for existing in _REGISTRY:
        if existing.name == cls.name:
            raise ValueError(
                f"tool name collision on '{cls.name}': "
                f"{existing.__module__}.{existing.__name__} vs "
                f"{cls.__module__}.{cls.__name__}"
            )

    _REGISTRY.append(cls)
    return cls


def all_tools() -> list[type[ITool]]:
    """Return registered tool classes in registration order."""
    return list(_REGISTRY)

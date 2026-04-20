"""Tool package — importing a tool module runs its ``@register_tool``.

Adding a new tool: create ``<name>.py`` with a ``@register_tool`` class,
then add one import line here. ``server.py`` imports this package to
populate the registry before serving.
"""

from mx_tracing.tools import list_sections as _list_sections  # noqa: F401
from mx_tracing.tools import protect_and_trace as _protect_and_trace  # noqa: F401

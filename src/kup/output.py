from typing import TYPE_CHECKING
import json
import rich

if TYPE_CHECKING:
    from typing import Any

_JSON_OUTPUT = False

def set_json_output(enabled: bool) -> None:
    global _JSON_OUTPUT
    _JSON_OUTPUT = enabled

def is_json_output() -> bool:
    return _JSON_OUTPUT

def print_human(rich_data: Any) -> None:
    if not _JSON_OUTPUT:
        rich.print(rich_data)

def print_machine(json_data: dict[str, Any]) -> None:
    if _JSON_OUTPUT:
        print(json.dumps(json_data, indent=2), end=',\n')
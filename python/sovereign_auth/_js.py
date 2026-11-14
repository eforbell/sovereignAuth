"""The few JavaScript semantics the wire contract leans on, spelled out so this port decides exactly as the
Node library does: what String.prototype.trim() strips, what Number.isSafeInteger() accepts, and what
JSON.parse() refuses. Python's own defaults differ on each (str.strip() strips U+001C-U+001F but not
U+FEFF; True == 1; json.loads() reads NaN)."""

from __future__ import annotations

import json
from typing import Any

# ECMAScript WhiteSpace and LineTerminator, the set trim() removes.
JS_WHITESPACE = (
    "\t\n\x0b\x0c\r \xa0            "
    "    　﻿"
)

MAX_SAFE_INTEGER = 2**53 - 1


def js_trim(value: str) -> str:
    return value.strip(JS_WHITESPACE)


def is_number(value: Any) -> bool:
    """A JSON number: int or float, never bool (bool is an int in Python)."""
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def safe_integer(value: Any) -> int | None:
    """The value as an int if Number.isSafeInteger() would accept it, else None. JSON's 7.0 or 7e0 is 7 in
    JavaScript, so an integral float counts."""
    if not is_number(value):
        return None
    if isinstance(value, float):
        if not value.is_integer():
            return None
        value = int(value)
    return value if -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER else None


def _no_constant(name: str) -> Any:
    raise ValueError(f"{name} is not JSON")


def parse_json(text: str) -> Any:
    """JSON.parse(): no NaN or Infinity. Raises ValueError (json.JSONDecodeError is one)."""
    return json.loads(text, parse_constant=_no_constant)

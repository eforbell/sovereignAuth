"""The few JavaScript semantics the wire contract leans on, spelled out so this port decides exactly as the
Node library does: what String.prototype.trim() strips, what Number.isSafeInteger() accepts, and what
JSON.parse() refuses. Python's own defaults differ on each (str.strip() strips U+001C-U+001F but not
U+FEFF; True == 1; json.loads() reads NaN)."""

from __future__ import annotations

import json
import math
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


def _parse_int(text: str) -> int | float:
    # JSON.parse reads every number as a double. Past 17 digits nothing is a safe integer anyway, and float()
    # has no digit limit, where int() refuses more than 4300 digits by default.
    return int(text) if len(text) <= 17 else float(text)


def parse_json(text: str) -> Any:
    """JSON.parse(): no NaN or Infinity. Raises ValueError (json.JSONDecodeError is one), or RecursionError on
    nesting deeper than Python's stack allows, which callers treat as malformed."""
    return json.loads(text, parse_constant=_no_constant, parse_int=_parse_int)


def to_string(value: Any) -> str:
    """String(value) for the values a header or method can hold: text, numbers, booleans, None, and lists,
    which JavaScript joins with ',' (nested ones too), writing null and undefined as nothing."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (list, tuple)):
        return ",".join("" if item is None else to_string(item) for item in value)
    if is_number(value):
        return number_to_string(value)
    # Any other object: what Object.prototype.toString gives a plain object, never Python's repr, which
    # could carry text (a cookie, say) that JavaScript would not.
    return "[object Object]"


def number_to_string(value: int | float) -> str:
    """Number.prototype.toString(): the shortest digits that round-trip (Python's repr finds the same ones),
    laid out by ECMAScript's Number::toString rules."""
    number = float(value)
    if number != number:
        return "NaN"
    if number in (math.inf, -math.inf):
        return "Infinity" if number > 0 else "-Infinity"
    if number == 0:
        return "0"
    sign = "-" if number < 0 else ""
    mantissa, _, exponent = repr(abs(number)).partition("e")
    whole, _, fraction = mantissa.partition(".")
    digits = (whole + fraction).lstrip("0")
    point = len(whole) + int(exponent or 0) - (len(whole + fraction) - len((whole + fraction).lstrip("0")))
    digits = digits.rstrip("0") or "0"
    k, n = len(digits), point
    if k <= n <= 21:
        text = digits + "0" * (n - k)
    elif 0 < n <= 21:
        text = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        text = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        text = (digits if k == 1 else digits[0] + "." + digits[1:]) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + text

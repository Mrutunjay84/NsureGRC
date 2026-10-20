"""Strict JSON request parsing.

Rejects, with a clean 400 instead of a server error:
* NUL characters and unpaired surrogates in ANY string (PostgreSQL text cannot hold NUL; surrogates cannot be UTF-8 encoded),
* pathological nesting (the recursive stdlib decoder would otherwise raise RecursionError => HTTP 500),
* non-object/array roots are left to the serializers (they reject them).
"""
from __future__ import annotations

import json

from rest_framework.exceptions import ParseError
from rest_framework.parsers import JSONParser

MAX_DEPTH = 32


def _check_string(s: str) -> None:
    if "\x00" in s:
        raise ParseError("invalid characters")
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        raise ParseError("invalid characters") from None


def _validate(root) -> None:
    stack = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        if depth > MAX_DEPTH:
            raise ParseError("document too deeply nested")
        if isinstance(node, str):
            _check_string(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                _check_string(k)
                stack.append((v, depth + 1))
        elif isinstance(node, list):
            stack.extend((v, depth + 1) for v in node)


class StrictJSONParser(JSONParser):
    def parse(self, stream, media_type=None, parser_context=None):
        try:
            data = super().parse(stream, media_type, parser_context)
        except RecursionError:
            raise ParseError("document too deeply nested") from None
        except (ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, ParseError):
                raise
            raise ParseError("malformed JSON") from None
        _validate(data)
        return data

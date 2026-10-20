"""Harness for EXECUTABLE SPECIFICATIONS of controls that are NOT IMPLEMENTED (P2-3).

A spec test is written against the interface the implementation plan (`docs/plans/P2-3_IMPLEMENTATION_PLANS.md`) commits to. Until the
feature exists the test raises `FeatureAbsent` at its first `require_*` call and pytest records it as **xfail** - never as a pass.

Guard rails against fake coverage:
* `xfail(raises=FeatureAbsent, strict=True)`: ANY other exception (typo, broken fixture, wrong assertion) is a real FAILURE, and a spec
  that unexpectedly PASSES also fails the run, which forces the owner to delete the marker and flip the control to implemented
  deliberately, with the plan's definition of done in hand.
* Reports count xfail separately (`SECURITY_TEST_REPORT.md`); a control with only pending specs stays NOT IMPLEMENTED.
* The part of a spec body that follows the `require_*` call has NOT been executed against any implementation. It is a reviewed
  statement of required behaviour, not evidence that the behaviour exists.
"""
from __future__ import annotations

import importlib

import pytest
from django.urls import Resolver404, resolve


class FeatureAbsent(Exception):
    """The feature a spec exercises does not exist yet."""


def pending(control_id: str, plan_ref: str):
    return pytest.mark.xfail(raises=FeatureAbsent, strict=True,
                             reason=f"NOT IMPLEMENTED - {control_id}; executable specification per {plan_ref}")


def require_route(path: str, prefix: str = "/api/v1") -> None:
    try:
        resolve(prefix + path)
    except Resolver404 as exc:
        raise FeatureAbsent(f"no route {prefix + path}") from exc


def require_symbol(spec: str):
    """`'package.module:attribute'` -> the attribute, or FeatureAbsent if that module/attribute does not exist."""
    mod, _, attr = spec.partition(":")
    try:
        m = importlib.import_module(mod)
    except ModuleNotFoundError as exc:
        if exc.name and (mod == exc.name or mod.startswith(exc.name + ".")):
            raise FeatureAbsent(f"module {mod} does not exist") from exc
        raise
    if not hasattr(m, attr):
        raise FeatureAbsent(f"{mod} has no attribute {attr}")
    return getattr(m, attr)

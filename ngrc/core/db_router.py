"""Class-based DB router (D-P0-009): every model declares which least-privilege connection serves it.

Fail closed: a model that declares no alias cannot be routed. Only the `owner` alias may run migrations.
"""
from __future__ import annotations

from django.core.exceptions import ImproperlyConfigured


class ClassRouter:
    @staticmethod
    def _alias(model, attr: str) -> str:
        alias = getattr(model, attr, None)
        if alias is None:
            raise ImproperlyConfigured(f"{model.__name__} must declare {attr} (D-P0-009)")
        return alias

    def db_for_read(self, model, **hints):
        return self._alias(model, "ngrc_read_db")

    def db_for_write(self, model, **hints):
        return self._alias(model, "ngrc_write_db")

    def allow_relation(self, obj1, obj2, **hints):
        return getattr(type(obj1), "ngrc_read_db", None) == getattr(type(obj2), "ngrc_read_db", None)

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        return db == "owner"

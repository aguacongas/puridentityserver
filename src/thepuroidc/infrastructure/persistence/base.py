"""Fondations communes aux repositories SQL (SQLAlchemy 2.0 asynchrone)."""

from __future__ import annotations

from typing import cast

import sqlalchemy as sa
from sqlalchemy import make_url
from sqlalchemy.orm import DeclarativeBase

_ASYNC_DIALECTS = {
    "sqlite": "aiosqlite",
    "postgresql": "asyncpg",
    "mysql": "aiomysql",
}


class PersistenceBase(DeclarativeBase):
    """Base déclarative partagée par toutes les tables de persistance SQL."""


def async_dsn(dsn: str) -> str:
    """Adapte un DSN SQLAlchemy synchrone vers son dialecte asynchrone."""
    url = make_url(dsn)
    driver = _ASYNC_DIALECTS.get(url.get_backend_name())
    if driver is not None and url.drivername == url.get_backend_name():
        async_url = url.set(drivername=f"{url.get_backend_name()}+{driver}")
        return async_url.render_as_string(hide_password=False)
    return dsn


def migrate_add_missing_columns(connection: sa.Connection, model: type[PersistenceBase]) -> None:
    """Ajoute les colonnes du modèle absentes de la table existante (migration légère).

    ``create_all(checkfirst=True)`` ne modifie jamais une table présente : une base
    créée avec un schéma antérieur provoquerait un ``OperationalError: no such
    column`` à la lecture. On complète l'écart via ``ALTER TABLE ADD COLUMN``,
    sans toucher aux données.
    """
    table = cast(sa.Table, model.__table__)
    existing = {column["name"] for column in sa.inspect(connection).get_columns(table.name)}
    for column in table.columns:
        if column.name in existing:
            continue
        column_type = column.type.compile(dialect=connection.dialect)
        default = getattr(column.default, "arg", None) if column.default is not None else None
        default_clause = ""
        if default is not None:
            default_clause = f" DEFAULT {_sql_literal(default)}"
        null_clause = " NOT NULL" if column.nullable is False else ""
        add_column_sql = (
            f"ALTER TABLE {table.name} ADD COLUMN {column.name} "
            f"{column_type}{null_clause}{default_clause}"
        )
        connection.exec_driver_sql(add_column_sql)


def _sql_literal(value: object) -> str:
    """Rend un littéral SQL portable (booléens, entiers, chaînes)."""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return "'" + value.replace("'", "''") + "'"
    return str(value)

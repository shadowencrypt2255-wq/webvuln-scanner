"""Pagination helper shared by list endpoints."""
from __future__ import annotations

from typing import TypeVar

from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from app.schemas.common import Page

T = TypeVar("T")


def paginate(db: Session, stmt: Select, page: int, page_size: int, schema: type) -> Page:
    total = db.scalar(select(func.count()).select_from(stmt.order_by(None).subquery())) or 0
    rows = db.scalars(stmt.limit(page_size).offset((page - 1) * page_size)).all()
    return Page(
        items=[schema.model_validate(r) for r in rows],
        total=total, page=page, page_size=page_size,
    )

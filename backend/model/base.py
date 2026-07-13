"""Base types for the vendor-neutral configuration model."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid4())


class ModelObject(BaseModel):
    """Base class for every object in the vendor-neutral model."""

    id: str = Field(default_factory=_new_id)
    name: str
    description: str | None = None
    tags: list[str] = Field(default_factory=list)
    # Source metadata preserved for audit / explainability
    source_vendor: str | None = None
    source_ref: str | None = None  # original name / uuid / line reference
    source_raw: str | None = None  # optional original snippet (never required by generators)
    metadata: dict[str, Any] = Field(default_factory=dict)
    unsupported: bool = False
    unsupported_reason: str | None = None

    model_config = {"extra": "ignore"}


class NamedReference(BaseModel):
    """Lightweight reference to another model object by name and/or id."""

    id: str | None = None
    name: str
    kind: str | None = None  # e.g. "address", "service", "interface"

    model_config = {"extra": "ignore"}

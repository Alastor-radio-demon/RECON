from datetime import datetime
from uuid import UUID

from typing import Literal

from pydantic import BaseModel, Field


class Port(BaseModel):
    port: int
    protocol: str
    service: str
    product: str | None = None
    version: str | None = None


class Host(BaseModel):
    ip: str
    hostname: str | None = None
    status: Literal['pending', 'scanning', 'done'] = 'pending'
    ports: list[Port] = Field(default_factory=list)


class Scan(BaseModel):
    id: UUID
    cidr: str
    status: Literal['pending', 'discovering', 'completed', 'failed']
    created_at: datetime
    hosts: list[Host] = Field(default_factory=list)
    error: str | None = None


class ScanCreateRequest(BaseModel):
    cidr: str
    authorized: bool
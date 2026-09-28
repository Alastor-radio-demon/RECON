from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class Scan(BaseModel):
    id: UUID
    cidr: str
    status: str
    created_at: datetime


class ScanCreateRequest(BaseModel):
    cidr: str
    authorized: bool
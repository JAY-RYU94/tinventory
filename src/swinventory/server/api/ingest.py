from __future__ import annotations

from dataclasses import asdict
from typing import Callable

from fastapi import APIRouter, Depends

from swinventory.server.api.models import IngestSnapshot
from swinventory.server.services.ingest import IngestService


def build_router(service: IngestService, require_ingest: Callable[..., None]) -> APIRouter:
    router = APIRouter(prefix="/v1")

    @router.post("/ingest", dependencies=[Depends(require_ingest)])
    def ingest(body: IngestSnapshot) -> dict:
        return asdict(service.ingest(body.to_snapshot()))

    return router

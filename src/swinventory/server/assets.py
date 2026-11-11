"""자산 서비스: 저장소에서 대장·호스트·장비 정보를 읽어 AssetBook 을 만들고, 다른 목록에 자산 열을 붙인다."""
from __future__ import annotations

from typing import Any, Iterable

from swinventory.server.assetview import AssetBook
from swinventory.server.repo.base import InventoryRepository

# 호스트 목록류에 붙이는 열(상세 필드는 /v1/assets·호스트 상세에서 본다)
_LIST_COLUMNS = ("asset_id", "asset_no", "kind", "kind_source", "virt", "domain")


class AssetService:
    def __init__(self, repo: InventoryRepository):
        self._repo = repo

    def book(self) -> AssetBook:
        hosts = self._repo.list_hosts()
        return AssetBook(self._repo.list_assets(), hosts, self._repo.list_hardware(),
                         {h["host_id"]: set(h["ips"]) for h in hosts})

    def annotate(self, rows: Iterable[dict[str, Any]], book: AssetBook | None = None) -> list[dict[str, Any]]:
        """host_id 를 가진 행에 자산 열을 붙인다. 자산이 없어도 수집된 값(kind 등)이 채워지고 asset_no 만 None 이다."""
        book = book or self.book()
        out = list(rows)
        for r in out:
            view = book.host_view(r["host_id"])
            r.update({c: view[c] for c in _LIST_COLUMNS})
            r["asset_flags"] = view["flags"]
        return out

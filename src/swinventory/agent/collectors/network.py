from __future__ import annotations

from abc import ABC

from swinventory.agent.collectors.base import BaseCollector
from swinventory.common.models import ListeningPort, NetworkInterface


class InterfaceCollector(BaseCollector[list[NetworkInterface]], ABC):
    @property
    def name(self) -> str:
        return "network.interfaces"


class PortCollector(BaseCollector[list[ListeningPort]], ABC):
    @property
    def name(self) -> str:
        return "network.ports"

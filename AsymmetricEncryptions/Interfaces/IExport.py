from __future__ import annotations
from abc import ABC, abstractmethod

class IExport(ABC):
    @abstractmethod
    def export(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")

    @staticmethod
    @abstractmethod
    def load(self, *args, **kwargs):
        raise NotImplementedError("Function should be implemented inside of class")

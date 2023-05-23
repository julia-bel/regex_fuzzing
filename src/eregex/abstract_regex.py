from __future__ import annotations
from typing import Any, Optional, Iterator
from abc import ABC, abstractmethod
from graphviz import Digraph


class Regex(ABC):
    def __init__(self, value: Any):
        assert value, "empty regular expression"
        self.value = value
        self.name  = ""

    def __len__(self) -> int:
        return len(self.value)

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        pass


class NodeRegex(Regex):
    def __init__(self, value: Any):
        super(NodeRegex, self).__init__(value)
        self.unpack()

    @abstractmethod
    def unpack(self):
        pass

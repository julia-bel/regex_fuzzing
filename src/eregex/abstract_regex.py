from __future__ import annotations
from typing import Any, Optional, Iterator

import re

from abc import ABC, abstractmethod
from graphviz import Digraph


class Regex(ABC):
    def __init__(self, value: Any, group: bool = False):
        self.value = value
        self.name  = ""
        self.group = group
        self.substitution = None

    def match(self, word: str) -> bool:
        return re.match("^" + str(self) + "$", word)
    
    def substitute(self, word: Optional[str]) -> None:
        self.substitution = word

    def delete_group(self):
        self.group = False

    def get_substitution(self) -> str:
        return self.substitution

    def __len__(self) -> int:
        return len(self.value)
    
    @abstractmethod
    def delete_substitution(self):
        pass

    @abstractmethod
    def __str__(self) -> str:
        pass

    @abstractmethod
    def reverse(self) -> Regex:
        pass

    @abstractmethod
    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        pass


class NodeRegex(Regex):
    def __init__(self, value: Any, group: bool = False):
        super(NodeRegex, self).__init__(value, group)
        self.unpack()

    @abstractmethod
    def unpack(self):
        pass

from __future__ import annotations
from typing import List, Optional, Iterator
from graphviz import Digraph

from src.utils import key_generator
from src.eregex.abstract_regex import Regex, NodeRegex


class BaseRegex(Regex):
    def __str__(self) -> str:
        return self.value
    
    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        if name_generator is None:
            name_generator = key_generator()
        self.name = next(name_generator)
        graph.node(self.name, self.__class__.__name__)
        if parent is not None:
            graph.edge(parent, self.name)
        value = next(name_generator)
        graph.node(value, self.value)
        graph.edge(self.name, value)
        return graph
    

class BackrefRegex(Regex):
    """Stores reference to regex group"""
    def __init__(self, value: str, regex_value: Regex):
        super().__init__(value)
        self.regex_value = regex_value

    def __str__(self) -> str:
        return self.value
    
    def __len__(self) -> int:
        return 1
    
    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        if name_generator is None:
            name_generator = key_generator()
        self.name = next(name_generator)
        graph.node(self.name, self.__class__.__name__)
        if parent is not None:
            graph.edge(parent, self.name)
        graph.edge(self.name, self.regex_value.name)
        return graph


class ConcatenationRegex(NodeRegex):
    def __init__(self, value: List[Regex]):
        super().__init__(value)
        self.unpack()

    def __str__(self) -> str:
        if self.flat_len() == 1:
            return str(self.value[0])
        return "".join([str(v) if len(v) == 1 or not isinstance(v, AlternativeRegex)
                        else f"({v})" for v in self.value])

    def __len__(self) -> int:
        return sum([len(v) for v in self.value])

    def flat_len(self) -> int:
        return len(self.value)

    def unpack(self):
        while self.flat_len() == 1 and isinstance(self.value[0], ConcatenationRegex):
            self.value = self.value[0].value

    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        if name_generator is None:
            name_generator = key_generator()
        self.name = next(name_generator)
        graph.node(self.name, self.__class__.__name__)
        if parent is not None:
            graph.edge(parent, self.name)
        for v in self.value:
            v.plot(self.name, graph, name_generator)
        return graph


class AlternativeRegex(NodeRegex):
    def __init__(self, value: List[Regex]):
        super().__init__(value)

    def __str__(self) -> str:
        return "|".join([str(v) for v in self.value])

    def unpack(self):
        pass

    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        if name_generator is None:
            name_generator = key_generator()
        self.name = next(name_generator)
        graph.node(self.name, self.__class__.__name__)
        if parent is not None:
            graph.edge(parent, self.name)
        for v in self.value:
            v.plot(self.name, graph, name_generator)
        return graph


class StarRegex(NodeRegex):
    def __init__(self, value: Regex):
        NodeRegex.__init__(self, value)

    def __len__(self) -> int:
        return 1

    def __str__(self) -> str:
        return f"({self.value})*" if len(self.value) > 1 else f"{self.value}*"

    def unpack(self):
        pass

    def plot(
        self,
        parent: Optional[str] = None,
        graph: Digraph = Digraph(),
        name_generator: Optional[Iterator[str]] = None) -> Digraph:
        if name_generator is None:
            name_generator = key_generator()
        self.name = next(name_generator)
        graph.node(self.name, self.__class__.__name__)
        if parent is not None:
            graph.edge(parent, self.name)
        self.value.plot(self.name, graph, name_generator)
        return graph

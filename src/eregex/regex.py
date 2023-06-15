from __future__ import annotations
from typing import List, Optional, Iterator, Dict
from graphviz import Digraph

from src.eregex.utils import key_generator
from src.eregex.abstract_regex import Regex, NodeRegex


class BaseRegex(Regex):
    def __str__(self) -> str:
        if self.substitution is not None: return self.substitution
        return "(" + self.value + ")" if self.group else self.value

    def delete_substitution(self):
        self.substitute(None)
    
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
    
    def reverse(self) -> BaseRegex:
        return BaseRegex(self.value[::-1])
    

class BackrefRegex(Regex):
    """Stores reference to regex group"""
    def __init__(self, value: str, regex_value: Regex, group: bool = False):
        super().__init__(value, group)
        self.regex_value = regex_value

    def __str__(self) -> str:
        if self.substitution is not None: return self.substitution
        return "(" + self.value + ")" if self.group else self.value
    
    def substitute(self, word: str | None):
        super().substitute(word)
        self.regex_value.substitute(word)

    def delete_substitution(self):
        self.substitute(None)
        self.regex_value.delete_substitution()
    
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
    
    def reverse(self):
        pass


class ConcatenationRegex(NodeRegex):
    def __init__(self, value: List[Regex], group: bool = False):
        super().__init__(value, group)
        self.unpack()

    def __str__(self) -> str:
        if self.substitution is not None: return self.substitution
        if self.flat_len() == 1:
            string = str(self.value[0])
        else:
            string = "".join([str(v) if len(v) == 1 or not isinstance(v, AlternativeRegex)
                              else f"({v})" for v in self.value])
        return "(" + string + ")" if self.group else string

    def __len__(self) -> int:
        return sum([len(v) for v in self.value])

    def flat_len(self) -> int:
        return len(self.value)
    
    def sub(self, start: int = 0, end: Optional[int] = None) -> Regex:
        if start < len(self.value):
            return ConcatenationRegex(self.value[start:end])
        else:
            return BaseRegex("")

    def unpack(self):
        while self.flat_len() == 1 and isinstance(self.value[0], ConcatenationRegex):
            self.value = self.value[0].value

    def delete_group(self):
        self.group = False
        for value in self.value:
            value.delete_group()

    def delete_substitution(self):
        self.substitute(None)
        for value in self.value:
            value.delete_substitution()

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
    
    def reverse(self) -> ConcatenationRegex:
        return ConcatenationRegex([elem.reverse() for elem in self.value[::-1]])


class AlternativeRegex(NodeRegex):
    def __init__(self, value: List[Regex], group: bool = False):
        super().__init__(value, group)

    def __str__(self) -> str:
        if self.substitution is not None: return self.substitution
        string = "|".join([str(v) for v in self.value])
        return "(" + string + ")" if self.group else string

    def unpack(self):
        pass

    def delete_group(self):
        self.group = False
        for value in self.value:
            value.delete_group()

    def delete_substitution(self):
        self.substitute(None)
        for value in self.value:
            value.delete_substitution()

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
    
    def reverse(self) -> AlternativeRegex:
        return AlternativeRegex([elem.reverse() for elem in self.value])


class StarRegex(NodeRegex):
    def __init__(self, value: Regex, group: bool = False):
        NodeRegex.__init__(self, value, group)

    def __len__(self) -> int:
        return 1

    def __str__(self) -> str:
        if self.substitution is not None: return self.substitution
        string = f"({self.value})*" if len(self.value) > 1 and not self.value.group else f"{self.value}*"
        return "(" + string + ")" if self.group else string

    def unpack(self):
        pass

    def delete_group(self):
        self.group = False
        self.value.delete_group()

    def delete_substitution(self):
        self.substitute(None)
        self.value.delete_substitution()

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

    def reverse(self) -> StarRegex:
        return StarRegex(self.value.reverse())

# TODO: make better
def ext_to_classic(regex: Regex) -> str:
    if isinstance(regex, BaseRegex):
        return str(regex)
    if isinstance(regex, ConcatenationRegex):
        result = ""
        for value in regex.value:
            result += ext_to_classic(value)
        return result
    if isinstance(regex, AlternativeRegex):
        result = ""
        for value in regex.value:
            result += "|" + ext_to_classic(value)
        return f"({result})"
    if isinstance(regex, StarRegex):
        return f"({ext_to_classic(regex.value)})*"
    # if isinstance(regex, BackrefRegex):
    return ext_to_classic(regex.regex_value)

def ordered(regex: Regex, groups: Optional[Dict[Regex, str]] = None):
    if groups is None:
        groups = {}
    if regex.group:
        groups[regex] = "\\" + str(len(groups) + 1)
    if isinstance(regex, BackrefRegex):
        regex.value = groups[regex.regex_value]
    elif isinstance(regex, ConcatenationRegex) or isinstance(regex, AlternativeRegex):
        for value in regex.value:
            ordered(value, groups)
    elif isinstance(regex, StarRegex):
        ordered(regex.value, groups)

from __future__ import annotations
from typing import List, Optional, Iterator, Dict
from graphviz import Digraph

from src.eregex.utils import key_generator
from src.eregex.abstract_regex import Regex, NodeRegex


class BaseRegex(Regex):
    def __str__(self) -> str:
        if self.substitution is not None: return self.substitution
        return "(" + self.value + ")" if self.group else self.value
    
    def get_value_str(self) -> str:
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
    
    def get_value_str(self) -> str:
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
        return self.regex_value.reverse()


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
    
    def get_value_str(self) -> str:
        if self.flat_len() == 1:
            string = self.value[0].get_value_str()
        else:
            string = "".join([v.get_value_str() if len(v) == 1 or not isinstance(v, AlternativeRegex)
                else f"({v.get_value_str()})" for v in self.value])
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
    
    def get_value_str(self) -> str:
        string = "|".join([v.get_value_str() for v in self.value])
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
    
    def get_value_str(self) -> str:
        string = f"({self.value.get_value_str()})*" if len(self.value) > 1 and not self.value.group \
            else f"{self.value.get_value_str()}*"
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
        if regex.regex_value in groups:
            regex.value = groups[regex.regex_value]
        else:
            regex.value = regex.substitution if regex.substitution is not None else ""
    elif isinstance(regex, ConcatenationRegex) or isinstance(regex, AlternativeRegex):
        for value in regex.value:
            ordered(value, groups)
    elif isinstance(regex, StarRegex):
        ordered(regex.value, groups)


def copy_regex(regex: Regex) -> Dict[Regex, Regex]:
    if isinstance(regex, BaseRegex):
        return {regex: BaseRegex(regex.value)}
    if isinstance(regex, StarRegex):
        copy = copy_regex(regex.value)
        copy[regex] = StarRegex(copy[regex.value])
        return copy
    if isinstance(regex, AlternativeRegex):
        copy = {}
        for elem in regex.value:
            copy.update(copy_regex(elem))
        copy[regex] = AlternativeRegex([copy[r] for r in regex.value])
        return copy
    if isinstance(regex, ConcatenationRegex):
        copy = {}
        for elem in regex.value:
            copy.update(copy_regex(elem))
        copy[regex] = ConcatenationRegex([copy[r] for r in regex.value])
        return copy
    return {regex: BackrefRegex(regex.value, regex.regex_value)}


def deep_copy_regex(regex: Regex) -> Regex:

    def copy(regex: Regex, regex_copy: Dict[Regex, Regex]) -> Dict[Regex, Regex]:
        if isinstance(regex, BaseRegex):
            regex_copy[regex] = BaseRegex(regex.value)
        elif isinstance(regex, StarRegex):
            regex_copy = copy(regex.value, regex_copy)
            regex_copy[regex] = StarRegex(regex_copy[regex.value])
        elif isinstance(regex, AlternativeRegex):
            for elem in regex.value:
                copy(elem, regex_copy)
            regex_copy[regex] = AlternativeRegex([regex_copy[r] for r in regex.value])
        elif isinstance(regex, ConcatenationRegex):
            for elem in regex.value:
                copy(elem, regex_copy)
            regex_copy[regex] = ConcatenationRegex([regex_copy[r] for r in regex.value])
        elif regex.regex_value in regex_copy:
            regex_copy[regex] = BackrefRegex("", regex_copy[regex.regex_value])
            regex_copy[regex.regex_value].group = True
        else:
            regex_copy[regex] = BackrefRegex("", regex.regex_value)
        return regex_copy
    
    return copy(regex, {})[regex]


def get_substitutions(regex: Regex) -> Dict[Regex, str]:
    if isinstance(regex, BaseRegex):
        return {regex: regex.value}
    subs = {}
    if isinstance(regex, StarRegex):
        subs = get_substitutions(regex.value)
    elif isinstance(regex, AlternativeRegex) or isinstance(regex, ConcatenationRegex):
        for elem in regex.value:
            subs.update(get_substitutions(elem))
    if regex.substitution is not None:
        subs[regex] = regex.substitution
    return subs

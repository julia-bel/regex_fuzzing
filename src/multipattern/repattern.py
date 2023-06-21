from __future__ import annotations
from typing import List, Optional, Dict, Any

from src.eregex.parser import ERegexParser
from src.eregex.abstract_regex import Regex
from src.patterns_learning.pattern.abstract_pattern import Variable, Pattern


class REVariable(Variable):
    def __init__(self, regex: Regex, value: Optional[str | List[str]] = None):
        super().__init__(value)
        self.regex = regex

    def substitute(self, value: str | List[str]):
        assert self.regex.match(value if isinstance(str) else "".join(value))
        self.value = list(value) if isinstance(value, str) else value

    def match(self, word: str) -> bool:
        return self.regex.match(word)


class REPattern(Pattern):
    def __init__(self, value: List[str | REVariable]):
        super().__init__(value)
        self.vars_counter = self._count_vars()

    def _count_vars(self) -> Dict[REVariable, int]:
        vars = {}
        for value in self.value:
            if isinstance(value, REVariable):
                if value in vars:
                    vars[value] += 1
                else:
                    vars[value] = 0
        return vars
    
    def __str__(self) -> str:
        string, vars = self.shape(return_vars=True)
        return "".join(string) + ", " + ", ".join([f"{v} = {str(k.regex)}" for k, v in vars.items()])

    def sub(self, start: int = 0, end: Optional[int] = None) -> REPattern:
        return REPattern(self.value[start:end])

    def shape(self, var_id: str = "X", return_vars: bool = False) -> Any:
        result = []
        vars = {}
        i = 1
        for value in self.value:
            if isinstance(value, REVariable):
                prev_i = vars.get(value)
                if prev_i is None:
                    vars[value] = "[" + var_id + str(i) + "]"
                    result.append(vars[value])
                    i += 1
                else:
                    result.append(prev_i)
            else:
                result.append(value)
        if return_vars:
            return result, vars
        return result

    def slice_len(self, start: int = 0, end: Optional[int] = None) -> int:
        length = 0
        for value in self.value[start:end]:
            l = len(value)
            length += l if l > 0 else 1
        return length
    
    def get_regular_str(self) -> str:
        value = [elem if isinstance(elem, str) else str(elem.regex) for elem in self.value]
        return "".join(value)
    
    def get_regex(self) -> str:
        return ERegexParser(self.get_regular_str()).parse()
    
    def get_ext_regex(self) -> str:
        result = ""
        vars = {}
        for i, elem in enumerate(self.value):
            if isinstance(elem, str):
                result += elem
            elif elem in vars:
                result += f"\\{vars[elem]}"
            else:
                vars[elem] = i + 1
                result += str(elem.regex)
        return result

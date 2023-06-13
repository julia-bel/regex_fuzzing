from __future__ import annotations
from typing import List, Optional

from src.eregex.abstract_regex import Regex
from src.patterns_learning.pattern.abstract_pattern import Variable, Pattern


class RECVariable(Variable):
    def __init__(self, regex: Regex, value: Optional[str | List[str]] = None):
        super().__init__(value)
        self.regex = regex

    def substitute(self, value: str | List[str]):
        assert self.regex.match(value if isinstance(str) else "".join(value))
        self.value = list(value) if isinstance(value, str) else value

    def match(self, word: str) -> bool:
        return self.regex.match(word)


class RECPattern(Pattern):
    def __init__(self, value: List[str | RECVariable]):
        super().__init__(value)
        self.vars_counter = self._count_vars()

    
    def shape(self, var_id: str = "x", return_vars: bool = False) -> List[str]:
        result = []
        vars = {}
        i = 1
        for value in self.value:
            if isinstance(value, REVariable):
                prev_i = vars.get(value)
                if prev_i is None:
                    vars[value] = var_id + str(i)
                    result.append(vars[value])
                    i += 1
                else:
                    result.append(prev_i)
            else:
                result.append(value)
        if return_vars:
            result, vars
        return result

    
    def __str__(self) -> str:
        string, vars = self.shape(return_vars=True)
        return string + ", " + ", ".join([f"{v} = {str(k.regex)}" for k, v in vars])

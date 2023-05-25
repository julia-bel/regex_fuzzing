from __future__ import annotations
from typing import List, Optional

from src.eregex.abstract_regex import Regex
from src.patterns_learning.pattern.abstract_pattern import Variable, Pattern


class REVariable(Variable):
    def __init__(self, regex: Regex, value: Optional[str | List[str]] = None):
        super().__init__(value)
        self.regex = regex

    # def is_dictionary_compatible(self, word: str) -> bool:
    #     for elem in self.dictionary:
    #         if isinstance(elem, str):
    #             if elem == word:
    #                 return True
    #         else:
    #             if elem.match(word):
    #                 return True
    #     return False

    def substitute(self, value: str | List[str]):
        assert self.regex.match(value if isinstance(str) else "".join(value))
        self.value = list(value) if isinstance(value, str) else value


class REPattern(Pattern):
    def __init__(self, value: List[str | REVariable]):
        super().__init__(value)

    def shape(self, var_id: str = "x") -> List[str]:
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
        return result

    def slice_len(self, start: int = 0) -> int:
        length = 0
        for value in self.value[start:]:
            l = len(value)
            length += l if l > 0 else 1
        return length
    
    def get_regular_str(self) -> str:
        value = [elem if isinstance(elem, str) else str(elem.regex) for elem in self.value]
        return "".join(value)

from __future__ import annotations
from typing import List, Optional

from src.eregex.abstract_regex import Regex
from src.patterns_learning.pattern.abstract_pattern import Variable, Pattern


class REVariable(Variable):
    def __init__(self, alphabet: List[str|Regex], value: Optional[str | List[str]] = None):
        super().__init__(value)
        self.alphabet = alphabet

    def is_alphabet_compatible(self, word: str) -> bool:
        for elem in self.alphabet:
            if isinstance(elem, str):
                if elem == word:
                    return True
            else:
                if elem.match(word):
                    return True
        return False

    def substitute(self, value: str | List[str]):
        assert self.is_alphabet_compatible(value if isinstance(str) else "".join(value))
        self.value = list(value) if isinstance(value, str) else value


class REMultiPattern(Pattern):
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

  
def neighborhood_alphabet(var: REVariable, pattern: REMultiPattern, n: int = 0) -> List[str]:
    i = -1
    for i, elem in enumerate(pattern.value):
        if elem == var:
            break
    assert i > -1, "variable is not in pattern"
    alphabet = []
    for elem in pattern.value[i - n: i + n + 1]:
        if isinstance(elem, str):
            alphabet.append(elem)
        else:
            alphabet += elem.alphabet
    return alphabet

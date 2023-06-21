from __future__ import annotations
from typing import Optional, Dict

from src.eregex.regex import Regex


class RECPattern:
    def __init__(
        self,
        value: str,
        vars: Optional[Dict[str, RECPattern]] = None,
        history: Optional[Dict[Regex, str]] = None):
        self.value = value
        self.vars = {} if vars is None else self.simplify(value, vars)
        self.history = {} if history is None else history

    def simplify(self, value: str, vars: Dict[str, RECPattern]) -> Dict[str, RECPattern]:
        new_vars = {}
        for var, pattern in vars.items():
            if value.find(var) > -1:
                new_vars[var] = pattern
        return new_vars

    def get_all_vars(self) -> Dict[str, RECPattern]:
        all_vars = {}
        for var, pattern in self.vars.items():
            all_vars[var] = pattern
            for v, p in pattern.get_all_vars():
                all_vars[v] = p 
        return all_vars

    def __str__(self) -> str:
        result = self.value
        if len(self.vars) > 0:
            result += ", " + ", ".join([f"{k} = {v}" for k, v in self.vars.items()])
        return result

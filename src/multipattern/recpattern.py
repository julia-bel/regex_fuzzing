from __future__ import annotations
from typing import Dict


class RECPattern:
    def __init__(self, value: str, vars: Dict[str, RECPattern]):
        self.value = value
        self.vars = vars

    def get_all_vars(self) -> Dict[str, RECPattern]:
        all_vars = {}
        for var, pattern in self.vars.items():
            all_vars[var] = pattern
            for v, p in pattern.get_all_vars():
                all_vars[v] = p 
        return all_vars

    def __str__(self) -> str:
        return self.value + ", " + ", ".join([f"{k} = {v}" for k, v in self.vars])

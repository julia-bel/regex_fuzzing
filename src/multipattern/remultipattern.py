from __future__ import annotations
from typing import List, Callable

from src.multipattern.repattern import REPattern
from src.multipattern.recpattern import RECPattern


class REMultipattern:
    def __init__(self, value: List[REPattern|RECPattern]):
        self.value = value

    def add(self, value: REPattern|RECPattern):
        self.value.append(value)

    def update(self, other: REMultipattern):
        self.value += other.value

    def __str__(self) -> str:
        return "\n".join([str(v) for v in self.value])
    
    def apply(self, func: Callable):
        for i, value in enumerate(self.value):
            self.value[i] = func(value)

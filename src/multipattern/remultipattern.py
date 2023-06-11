from __future__ import annotations
from typing import List

from src.multipattern.repattern import REPattern


class REMultipattern:
    def __init__(self, value: List[REPattern]):
        self.value = value

    def add(self, value: REPattern):
        self.value.append(value)

    def update(self, other: REMultipattern):
        self.value += other.value

    def __str__(self) -> str:
        return "\n".join([str(v) for v in self.value])

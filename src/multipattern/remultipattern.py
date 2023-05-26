from __future__ import annotations
from typing import List

from src.multipattern.repattern import REPattern


class REMultipattern:
    def __init__(self, value: List[REPattern]):
        # TODO: make set(value)
        self.value = value

    def update(self, other: REMultipattern):
        self.value += other.value

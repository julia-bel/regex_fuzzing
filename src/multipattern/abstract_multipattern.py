from __future__ import annotations
from abc import ABC, abstractmethod
from typing import List, Optional


class Variable(ABC):
    def __init__(self, value: Optional[str | List[str]] = None):
        self.value = list(value) if isinstance(value, str) else value

    def is_free(self) -> bool:
        return self.value is None

    def free(self):
        self.value = None

    def __len__(self) -> int:
        return len(self.value) if self.value else 0

    def __str__(self) -> str:
        return "" if self.is_free() else "".join(self.value)

    @abstractmethod
    def substitute(self, value: str | List[str]):
        pass


class Pattern(ABC):
    def __init__(self, value: List[str | Variable]):
        assert value, "empty pattern"
        self.value = self._unfold(value)

    def _unfold(self, value: List[str | Variable]):
        result = []
        for v in value:
            if isinstance(v, str):
                result += list(v)
            else:
                result.append(v)
        return result

    def __len__(self) -> int:
        return len(self.value)

    def __str__(self) -> str:
        return "".join(self.shape())

    def __eq__(self, other: Pattern) -> bool:
        return self.shape() == other.shape()

    def free(self):
        for v in self.value:
            if not isinstance(v, str):
                v.free()

    @abstractmethod
    def shape(self) -> List[str]:
        pass

    @abstractmethod
    def match(self, word: str) -> bool:
        pass

    def include(self, pattern: Pattern) -> bool:
        pass
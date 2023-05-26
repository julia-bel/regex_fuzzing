from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod

from src.dynamic_analyzer.const import *
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.wrappers.multipattern_learner import MultipatternLearner


class Fuzzer(ABC):

    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        learner: MultipatternLearner):
        self.fuzzer = fuzzer
        self.learner = learner

    @abstractmethod
    def run(self, input: Any, n_neighbors: int = 3, first: bool = False) -> Any:
        pass

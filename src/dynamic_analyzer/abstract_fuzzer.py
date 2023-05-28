from __future__ import annotations
from typing import Any
from abc import ABC, abstractmethod

from src.dynamic_analyzer.const import *
from src.dynamic_analyzer.ambiguity_analyzer import AmbiguityAnalyzer
from src.wrappers.regex_matcher import RegexMatcher
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.wrappers.multipattern_learner import MultipatternLearner


class Fuzzer(ABC):

    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        matcher: RegexMatcher,
        ambiguity_analyzer: AmbiguityAnalyzer,
        learner: MultipatternLearner):
        self.fuzzer = fuzzer
        self.matcher = matcher
        self.ambiguity_analyzer = ambiguity_analyzer
        self.learner = learner

    @abstractmethod
    def run(self, input: Any, n_neighbors: int = 3, first: bool = False) -> Any:
        pass

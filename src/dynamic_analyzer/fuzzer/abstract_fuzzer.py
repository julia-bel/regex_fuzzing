from __future__ import annotations
from typing import Dict
from abc import ABC, abstractmethod

from src.multipattern.remultipattern import REMultipattern
from src.dynamic_analyzer.ambiguity_analyzer import AmbiguityAnalyzer
from src.wrappers.static_analyzer import StaticAnalyzer
from src.wrappers.regex_matcher import RegexMatcher
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.wrappers.multipattern_learner import REPatternLearner


class Fuzzer(ABC):
    """Main structured fuzzing algorithm implementation"""

    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        matcher: RegexMatcher,
        static_analyzer: StaticAnalyzer,
        ambiguity_analyzer: AmbiguityAnalyzer):
        self.fuzzer = fuzzer
        self.matcher = matcher
        self.static_analyzer = static_analyzer
        self.ambiguity_analyzer = ambiguity_analyzer
        # self.learner = learner

    @abstractmethod
    def run(self) -> Dict[int, REMultipattern]:
        pass

    @abstractmethod
    def pump(self):
        pass

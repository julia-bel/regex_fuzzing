from typing import Any, List, Iterator, Set

from src.wrappers.regex_matcher import RegexMatcher
from src.multipattern.repattern import REPattern, REVariable
from src.fuzzer.const import *
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.eregex.regex import (
    Regex, BaseRegex, BackrefRegex,
    StarRegex, AlternativeRegex, ConcatenationRegex)


class REPatternFuzzer:
    """Main structured fuzzing algorithm implementation"""  
    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        analyzer: StaticAnalyzer,
        learner: MultipatternLearner):
        self.fuzzer = fuzzer
        self.analyzer = analyzer
        self.learner = learner
        self.regex = None

    def run(self, pattern: REPattern) -> Any:
        pass # TODO: fuzz one or several vars in pattern
    
    def _open_regex(self, regex: Regex, rec_limit: int = 2) -> Iterator[str]:
        if isinstance(regex, BaseRegex):
            yield str(regex)
        elif isinstance(regex, AlternativeRegex):
            for value in regex.value:
                for child in self._open_regex(value):
                    yield child
        elif isinstance(regex, ConcatenationRegex):
            for first_child in self._open_regex(regex.value[0]):
                for last_child in self._open_regex(ConcatenationRegex(regex.value[1:])):
                    yield first_child + last_child
        elif isinstance(regex, StarRegex):
            for limit in range(rec_limit):
                for child in self._open_regex(regex.value, rec_limit):
                    yield limit * child
        else: # BackrefRegex
            for child in self._open_regex(regex.regex_value):
                yield child

    def _get_neighbors_dictionary(
        self,
        var: REVariable,
        pattern: REPattern,
        n_neighbors: int = 0) -> List[str]:
        i = -1
        for i, elem in enumerate(pattern.value):
            if elem == var:
                break
        assert i > -1, "variable is not in pattern"
        vars = set()
        dictionary = set()
        for elem in pattern.value[i - n_neighbors: i + n_neighbors + 1]:
            if isinstance(elem, str):
                dictionary.add(elem)
            elif elem not in vars:
                dictionary.update(self._get_regex_dictionary(elem.regex))
                vars.add(elem)
        return list(dictionary)

    def _get_regex_dictionary(self, regex: Regex) -> Set[str]:
        dictionary = set(word for word in self._open_regex(regex, rec_limit=2))
        return dictionary
    
    def cut(self, pattern: REPattern, var: REVariable, n_neighbors: int = 3):
        for i, elem in enumerate(pattern.value):
            if elem == var:

    def pump(self, pattern: REPattern, var: REVariable, n_neighbors: int = 3) -> Any:
        dictionary = self._get_neighbors_dictionary(var, pattern, n_neighbors)
        fuzzer = GeneticFuzzer(RegexMatcher(pattern.get_regular_str()), dictionary)
        return fuzzer.run(pattern, var)

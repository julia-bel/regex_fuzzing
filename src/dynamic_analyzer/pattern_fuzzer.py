from typing import List, Iterator, Set, Dict
import multiprocessing

from src.dynamic_analyzer.abstract_fuzzer import Fuzzer
from src.wrappers.regex_matcher import RegexMatcher
from src.multipattern.repattern import REPattern, REVariable
from src.multipattern.remultipattern import REMultipattern
from src.wrappers.multipattern_learner import MultipatternLearner
from src.const import *
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, AlternativeRegex, ConcatenationRegex)


class REPatternFuzzer(Fuzzer):
    """Main structured fuzzing algorithm implementation"""  
    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        learner: MultipatternLearner):
        super().__init__(fuzzer, learner)

    def run(
        self,
        input: REPattern,
        n_neighbors: int = 3,
        first: bool = False) -> Dict[int, REMultipattern]:
        # TODO: make first amb return if first else full
        vars = set()
        pumping_groups = {}
        for elem in input.value:
            if isinstance(elem, str) or elem not in vars:
                result = self.cut(input, elem, n_neighbors)
                for amb, pattern in result.items():
                    if amb in pumping_groups:
                        pumping_groups[amb].update(pattern)
                    else:
                        pumping_groups[amb] = pattern
                vars.add(elem)
        return pumping_groups
 
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
        i: int,
        pattern: REPattern,
        n_neighbors: int = 0) -> List[str]:
        # i = -1
        # for i, elem in enumerate(pattern.value):
        #     if elem == var:
        #         break
        # assert i > -1, "variable is not in pattern"
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
    
    def _generate_values(
        self,
        var: REVariable, 
        dictionary: List[str],
        timeout: float = 0.5,
        num_generations: int = 10) -> List[str]:
        fitness_func = lambda x: var.match(x)
        genetic = GeneticFuzzer(dictionary, fitness_func)
        proc = multiprocessing.Process(target=genetic.evolve, args=(num_generations,))
        proc.start()
        proc.join(timeout)
        if proc.is_alive():
            proc.terminate()
            proc.join()
        return genetic.generation
    
    def cut(
        self,
        pattern: REPattern,
        var: REVariable,
        n_neighbors: int = 3,
        first: bool = False) -> Dict[int, REMultipattern]: 
        prev_i = -1
        max_ambiguity = NO_AMBIGUOUS
        pumping_groups = {}
        vars = set()
        for i, elem in enumerate(pattern.value):
            if elem == var:
                pumped = self.pump(i - prev_i - 1, pattern.sub(prev_i + 1), vars, n_neighbors)
                for amb, groups in pumped:
                    if max_ambiguity < amb:
                        max_ambiguity = amb
                        pumping_groups[max_ambiguity] = groups
                if result[0]:
                    if ambiguity
                    pumping_groups += result[1]
                prev_i = i
            if isinstance(elem, REVariable):
                vars.add(elem)

        return pumping_groups

    def pump(
        self,
        i: int,
        pattern: REPattern,
        vars: Set[REVariable],
        n_neighbors: int = 3,
        timeout: float = 0.5,
        first: bool = False) -> Dict[int, List[List[str]]]: 
        # returns Dict[ambiguity status, pumping multipattern]

        # generation of var values
        var_subs = {}
        for j, elem in enumerate(pattern.value[i]):
            if elem in vars:
                dictionary = self._get_neighbors_dictionary(j, pattern, n_neighbors)
                subs = self._generate_values(pattern.value[j], dictionary, timeout)
                if elem in var_subs:
                    var_subs[elem].update(subs)
                else:
                    var_subs[elem] = subs

        # generation of attack
        matcher = RegexMatcher()
        regex = pattern.get_regular_str()
        for sub in subs:
            fitness_func = lambda x: matcher.match(regex, x + END_MARKER) / len(x + END_MARKER) 
            fuzzer = GeneticFuzzer(dictionary, fitness_func)
        return 
    
    

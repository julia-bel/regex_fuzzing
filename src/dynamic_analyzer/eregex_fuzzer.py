from typing import Any, List, Dict, Tuple, Iterator


from src.dynamic_analyzer.const import *
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.wrappers.static_analyzer import StaticAnalyzer
from src.eregex.parser import ERegexParser
from src.wrappers.multipattern_learner import MultipatternLearner
from src.eregex.regex import (
    Regex, BaseRegex, BackrefRegex,
    StarRegex, AlternativeRegex, ConcatenationRegex)


class ERegexFuzzer:
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

    def run(self, regex_string: str) -> Any:       
        parser = ERegexParser(regex_string)
        self.regex = parser.parse()
        self.process(self.regex, parser.capture_groups)

    def _check_star_outside(self, target: Regex, source: Regex) -> bool:

        def star_contains(target: Regex, source: Regex) -> Tuple[bool, bool]: # (contains, star)
            if target == source:
                return True, False
            if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
                for value in source.value:
                    if target == value:
                        return True, False
                    contains = star_contains(target, value)
                    if contains[0]:
                        return contains
            elif isinstance(source, StarRegex):
                return star_contains(target, source.value)[0], True
            else:
                return target == source, False
            return False, False
        
        return all(star_contains(target, source))
    
    def _check_star_inside(self, source: Regex) -> bool:
        if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
            for value in source.value:
                if self._check_star_inside(value):
                    return True
        elif isinstance(source, StarRegex):
            return True
        return False

    def _check_group_type(self, group: Regex, regex: Regex) -> int:
        outside = self._check_star_outside(group, regex)
        inside = self._check_star_inside(group)
        if outside and inside:
            return ABOUT
        if outside:
            return OUT
        if inside:
            return IN
        return NO
    
    def _check_backref_type(self, backref: Regex, regex: Regex) -> int:
        return OUT if self._check_star_outside(backref, regex) else NO
    
    def _open_regex(self, regex: Regex, rec_limit: int) -> Iterator[str]:
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
            pass
        else: # BackrefRegex
            for child in self._open_regex(regex.regex_value):
                yield child

    def _process_classic_part(
        self,
        regex: Regex,
        capture_groups: Dict[str, Regex],
        processed: str = "",
        regexes: List[Regex] = None) -> int:
        if regexes is None:
            regexes = []
        if isinstance(regex, BaseRegex):
            return 1
        if isinstance(regex, StarRegex):
            if self.process(regex.value, capture_groups) or self.analyzer(str(regex)):
                return self.analyzer(processed + str(regex))
            return 0
        if isinstance(regex, AlternativeRegex):
            curr_processed = ""
            for value in regex.value:
                if self.process(value, capture_groups, curr_processed):
                    curr_processed += "|" + str(value)
                    if not self.analyzer(curr_processed):
                        return 0
                else:
                    return 0
            return self.analyzer(processed + str(regex))
        if isinstance(regex, ConcatenationRegex):
            curr_processed = ""
            for value in regex.value:
                if self.process(value, capture_groups, curr_processed):
                    curr_processed += str(value)
                    if not self.analyzer(curr_processed):
                        return 0
                else:
                    return 0
            return self.analyzer(processed + str(regex))
        
    def _procces_memory_part(
        self,
        regex: Regex,
        capture_groups: Dict[str, Regex],
        processed: str = "",
        regexes: List[Regex] = None) -> int:
        
        backref_type = self._check_backref_type(regex, self.regex)
        group_type = self._check_group_type(regex.group, self.regex)
        if group_type == OUT:
            if backref_type == OUT:
                # substitution vs 1 + a*a
            else:
                # substitution
        elif group_type == IN:
            if backref_type == OUT:
                # axis then diags
            else:
                # cuttion
        elif group_type == ABOUT:
            if backref_type == OUT:
                pass
            else:
                # cuttion vs 1 + a*a
        else:
            if backref_type == OUT:
                # substitution
            else:
                # no attack
        # TODO: replace current string value
        return
    
    def process(
        self,
        regex: Regex,
        capture_groups: Dict[str, Regex],
        processed: str = "",
        regexes: List[Regex] = None) -> int:
        pass
        

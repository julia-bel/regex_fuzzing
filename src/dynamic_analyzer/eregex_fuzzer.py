from typing import Any, List, Dict, Tuple, Iterator

from src.const import *
from src.dynamic_analyzer.const import *
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.wrappers.static_analyzer import StaticAnalyzer
from src.dynamic_analyzer.ambiguity_analyzer import AmbiguityAnalyzer
from src.wrappers.regex_matcher import RegexMatcher
from src.eregex.parser import ERegexParser
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, AlternativeRegex, ConcatenationRegex, BackrefRegex)


class ERegexFuzzer:
    """Main structured fuzzing algorithm implementation"""  
    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        matcher: RegexMatcher,
        analyzer: StaticAnalyzer,
        ambiguity_analyzer: AmbiguityAnalyzer):
        self.super().__init__(fuzzer, matcher, ambiguity_analyzer)
        self.analyzer = analyzer
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
        else: # BackrefRegex - ???
            for child in self._open_regex(regex.regex_value):
                yield child

    # def _process_classic_part(
    #     self,
    #     regex: Regex,
    #     capture_groups: Dict[str, Regex],
    #     processed: str = "",
    #     regexes: List[Regex] = None) -> int:
    #     if regexes is None:
    #         regexes = []
    #     if isinstance(regex, BaseRegex):
    #         return 1
    #     if isinstance(regex, StarRegex):
    #         if self.process(regex.value, capture_groups) or self.analyzer(str(regex)):
    #             return self.analyzer(processed + str(regex))
    #         return 0
    #     if isinstance(regex, AlternativeRegex):
    #         curr_processed = ""
    #         for value in regex.value:
    #             if self.process(value, capture_groups, curr_processed):
    #                 curr_processed += "|" + str(value)
    #                 if not self.analyzer(curr_processed):
    #                     return 0
    #             else:
    #                 return 0
    #         return self.analyzer(processed + str(regex))
    #     if isinstance(regex, ConcatenationRegex):
    #         curr_processed = ""
    #         for value in regex.value:
    #             if self.process(value, capture_groups, curr_processed):
    #                 curr_processed += str(value)
    #                 if not self.analyzer(curr_processed):
    #                     return 0
    #             else:
    #                 return 0
    #         return self.analyzer(processed + str(regex))

    def _check_type_inside(self, source: Regex, type: Any) -> bool:
        if isinstance(source, type):
            return True
        if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
            for value in source.value:
                if self._check_type_inside(value, type):
                    return True
        return False

    def procces_memory_part(self, regex: Regex, backrefs: List[Regex]) -> Any:
        for mem in backrefs:
            # status = self.process(mem)
            status = self._procces_basic_memory(mem)
            if status > NO_AMBIGUOUS:
                return status

        # if isinstance(regex, BaseRegex):
        #     return NO_AMBIGUOUS
        # if isinstance(regex, StarRegex):
        #     status = self.process(regex.value, capture_groups)
        #     if status == NO_AMBIGUOUS:
        #         return self.analyzer(processed + str(regex))
        #     return status
        # if isinstance(regex, AlternativeRegex):
        #     # curr_processed = ""
        #     # for value in regex.value:
        #     #     status = self.process(value, capture_groups)
        #     #     if status == NO_AMBIGUOUS:
        #     #         curr_processed += "|" + str(value)
        #     #         if not self.analyzer(curr_processed):
        #     #             return 0
        #     #     else:
        #     #         return 0
        #     return self.analyzer(processed + str(regex))
        # if isinstance(regex, ConcatenationRegex):
        #     curr_processed = ""
        #     for value in regex.value:
        #         if self.process(value, capture_groups, curr_processed):
        #             curr_processed += str(value)
        #             if not self.analyzer(curr_processed):
        #                 return 0
        #         else:
        #             return 0
        #     return self.analyzer(processed + str(regex))

    def kleene_open(self, regex: StarRegex) -> str:
        return f"(|{str(regex)}{str(regex.value)})"
    
    def substitution(self, regex: BackrefRegex) -> Iterator[str]:
        return self._open_regex(regex.regex_value)
        
    def _procces_basic_memory(
        self,
        regex: Regex,
        back: Regex,
        capture_groups: Dict[str, Regex],
        processed: str = "",
        regexes: List[Regex] = None) -> int:
        
        backref_type = self._check_backref_type(back, regex)
        group_type = self._check_group_type(back.group, regex)
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
    
    def pump(self):
        pass
    
    def run(self, regex: Regex, capture_groups: Dict[str, Regex]) -> Any:
        self.regex = regex
        return self.process(regex)
    
    def process(
        self,
        regex: Regex,
        capture_groups: Dict[str, Regex],
        regexes: List[Regex] = None) -> int:
        if isinstance(regex, StarRegex):
            status = self.run(regex.value, capture_groups)
            if status > NO_AMBIGUOUS:
                return status
            if self._check_type_inside(regex.value, BackrefRegex):
                return self.pump(regex)
            else:
                return self.analyzer.analyze(str(regex))
        if isinstance(regex, AlternativeRegex):
            if not self._check_type_inside(regex.value, BackrefRegex):
                return self.analyzer.analyze(str(regex))
            else:
                for value in regex.value:
                    status = self.run(value, capture_groups)
                    if status > NO_AMBIGUOUS:
                        return status
            return NO_AMBIGUOUS
        if isinstance(regex, ConcatenationRegex):
            if not self._check_type_inside(regex.value, BackrefRegex):
                return self.analyzer.analyze(str(regex))
            else:
                before = ""
                backrefs = []
                for value in regex.value:
                    if not self._check_type_inside(value, BackrefRegex):
                        status = self.analyzer.analyze(before + str(value))
                        if status > NO_AMBIGUOUS:
                            return status
                        before += str(value)
                    else:
                        backrefs.append(value)
                return self._procces_memory_part(backrefs)
        return NO_AMBIGUOUS
    
    def process(
        self,
        regex: Regex,
        capture_groups: Dict[str, Regex],
        processed: str = "",
        regexes: List[Regex] = None) -> int:
        if regexes is None:
            regexes = []
        if isinstance(regex, BaseRegex):
            return NO_AMBIGUOUS
        if isinstance(regex, StarRegex):
            status = self.process(regex.value, capture_groups)
            if status == NO_AMBIGUOUS:
                return self.analyzer(processed + str(regex))
            return status
        if isinstance(regex, AlternativeRegex):
            # curr_processed = ""
            # for value in regex.value:
            #     status = self.process(value, capture_groups)
            #     if status == NO_AMBIGUOUS:
            #         curr_processed += "|" + str(value)
            #         if not self.analyzer(curr_processed):
            #             return 0
            #     else:
            #         return 0
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
        else:

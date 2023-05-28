from typing import List, Set, Dict, Tuple, Optional, Iterator
import random
import re

from src.eregex.parser import ERegexParser
from src.dynamic_analyzer.utils import get_last
from src.dynamic_analyzer.abstract_fuzzer import Fuzzer
from src.multipattern.repattern import REPattern, REVariable
from src.multipattern.remultipattern import REMultipattern
from src.const import *
from src.eregex.regex import Regex, BaseRegex, AlternativeRegex, ConcatenationRegex


class REPatternFuzzer(Fuzzer):
    """Main structured fuzzing algorithm implementation"""

    def _open_regex(self, regex: Regex, rec_limit: int = 1) -> Iterator[str]:
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
        else: # isinstance(regex, StarRegex):
            for limit in range(rec_limit):
                for child in self._open_regex(regex.value, rec_limit):
                    yield limit * child
        # no BackrefRegex
    
    def _get_regex_first_k(self, regex: Regex, k: int) -> Tuple[Set[str], Set[str]]:
        exact = set()
        sub = set() 
        if isinstance(regex, BaseRegex):
            if k == 1:
                exact.add(str(regex))
        elif isinstance(regex, AlternativeRegex):
            for value in regex.value:
                e, s = self._get_regex_first_k(value, k)
                exact.update(e)
                sub.update(s)
        elif isinstance(regex, ConcatenationRegex):
            e, s = self._get_regex_first_k(regex.value[0], k)
            sub.update(e, s)
            for part in range(k):
                prefix, _ = self._get_regex_first_k(regex.value[0], part)
                suffix_e, suffix_s = self._get_regex_first_k(regex.sub(1), k - part)
                exact.update(set(p + s for p in prefix for s in suffix_e))
                sub.update(set(p + s for p in prefix for s in suffix_s))
        else: # if isinstance(regex, StarRegex):
            if k == 0:
                exact.add("")
            e, s = self._get_regex_first_k(regex.value, k)
            exact.update(e)
            sub.update(s)
            for part in range(k):
                e, s = self._get_regex_first_k(regex.value, part)
                for i in range(k // part):
                    mod = k % i
                    if mod == 0:
                        exact.update(set(item * i for item in e))
                    else:
                        ex, s = self._get_regex_first_k(regex.value, mod)
                        exact.update(set(prefix * i + suffix for prefix in e for suffix in ex.union(s)))
        # no BackrefRegex
        return exact, sub
    
    def _get_regex_last_k(self, regex: Regex, k: int) -> Tuple[Set[str], Set[str]]:
        exact, sub = self._get_regex_first_k(regex.reverse(), k)
        exact = set(e[::-1] for e in exact)
        sub = set(s[::-1] for s in sub)
        return exact, sub

    def get_neighborhood(
        self,
        i: int,
        pattern: REPattern,
        k: int,
        n: int = 0) -> Set[str]:
        """Getting of left n-k-neighborhood

        Args:
            i (int): element index in pattern
            pattern (REPattern): pattern
            k (int): string (neighborhood) length
            n (int, optional): length of previous suffix == length current prefix. Defaults to 0.

        Returns:
            List[str]: n-k-neighborhood
        """

        elem = pattern.value[i]
        if n == 0:
            if isinstance(elem, REVariable):
                return self._get_regex_first_k(elem.regex, k)[0]
            else:
                result = self._get_regex_first_k(pattern.sub(i).get_regex(), k)
                return result[0].union(result[1])
        prefix = self._get_regex_last_k(pattern.sub(end = i).get_regex(), n)
        suffix = self._get_regex_first_k(pattern.sub(start = i).get_regex(), k - n)
        neighborhood = set(p + s for p in prefix for s in suffix)
        return neighborhood
    
    def pump_neighborhood(
        self,
        pattern: REPattern,
        start: int,
        end: int,
        max_radius: int = 10,
        top_k: int = 5) -> Optional[List[str]]:
        intersections = set()
        for k in range(max_radius):
            x1 = self.get_neighborhood(start, pattern, k)
            x2 = self.get_neighborhood(end, pattern, k)
            cap = x1.intersection(x2)
            if len(cap) == 0:
                return
            if end - start > 1:
                for n in range(k // 2):
                    trans = self.get_neighborhood(start, pattern, k, n)
                    cap = cap.intersection(trans)
                    if len(cap) == 0:
                        return
            if len(intersections) < top_k:
                intersections.update(cap)
        return sorted(intersections)
    
    def pump(
        self,
        pattern: REPattern,
        start: int,
        end: int,
        intersection: List[str],
        timeout: float = 0.5,
        evolution: bool = False, 
        num_epochs: int = 10,
        max_iter: int = 30) -> Optional[Tuple[int, REPattern]]:
        """Synchro pumping

        Args:
            pattern (REPattern)
            start (int): first var
            end (int): second var
            timeout (float, optional): defaults to 0.5.
            first (bool, optional): getting of first ambiguous. Defaults to False.

        Returns:
            Dict[int, REMultipattern]: [ambiguity status, pumping multipattern]
        """
        def format(attack_format: str, inter: str, subs: List[str], n: int = 2) -> str:
            for i, sub in enumerate(subs):
                word, bounds = sub
                pump = word[:bounds[0]] + word[bounds[0]:bounds[1]] * n + word[bounds[1]:]
                attack_format = attack_format.replace(f"{{{i}}}", pump)
            attack = attack_format.replace("{2}", inter * (2 * n))
            return attack
        
        def format_regex(attack_format: str, inter: str, subs: List[str]) -> REPattern:
            regex_subs = []
            for sub in subs:
                word, bounds = sub
                str_regex = f"{word[:bounds[0]]}({word[bounds[0]:bounds[1]]})*{word[bounds[1]:]}"
                regex_subs.append(REVariable(ERegexParser(str_regex).parse()))
            regex_subs.append(REVariable(ERegexParser(f"({inter})*").parse()))

            i = 0
            pattern = []
            while i < len(attack_format):
                if attack_format[i] != "{":
                    pattern.append(i)
                else:
                    pattern.append(regex_subs[int(attack_format[i+1])])
                    i += 1
                i += 1
            return REPattern(pattern)
        
        def shift_search(word: str, regex: str) -> str:
            return re.search(regex, word).group(0)
        
        target_vars = [pattern.value[start], pattern.value[end]]
        target_ids = [start, end]

        attack_format = ""
        for i, elem in enumerate(pattern.value):
            if isinstance(elem, str):
                attack_format += elem
            elif elem in target_vars:
                if i in target_ids:
                    attack_format += "{2}"
                else:
                    attack_format += "{0}" if elem == target_vars[0] else "{1}"
            else:
                attack_format += next(self._open_regex(elem.regex))
        last = get_last(pattern.get_regex())
        attack_format += random.choice(list(ALPHABET.difference(last)))

        ext_regex = pattern.get_ext_regex()
        max_score = -1
        result = []
        for inter in intersection:
            subs = []
            for var in target_vars:
                regex = str(var.regex)
                if evolution:
                    # TODO: full match
                    fitness_func = lambda x: self.matcher.match_word(x, regex)
                    subs.append(self.fuzzer.evolve(inter, fitness_func, num_epochs))
                else:
                    subword = shift_search(inter, regex)
                    subs.append((subword, [0, len(subword)]))
            word = format(attack_format, inter, subs, n=2)
            time = self.matcher.match_word(word, ext_regex, timeout)
            score = time / len(word)
            if score > max_score:
                max_score = score
                result = [inter, subs]
        
        times = []
        lens = []
        for n in range(1, max_iter):
            word = format(attack_format, result[0], result[1], n=n)
            lens.append(len(word))
            times.append(self.matcher.match_word(word, ext_regex, timeout))
        amb = self.ambiguity_analyzer.analyze(times, lens)
        if amb > NO_AMBIGUOUS:
            return amb, format_regex(attack_format, result[0], result[1])
    
    def run(
        self,
        pattern: REPattern,
        max_radius: int = 10,
        timeout: float = 0.8,
        first: bool = False) -> Dict[int, REMultipattern]:
        prev = None
        pumping_groups = {}
        for i, elem in enumerate(pattern.value):
            if isinstance(elem, REVariable):
                if prev is not None:
                    result = self.pump_neighborhood(pattern, prev, i, max_radius)
                    if result is None:
                        continue
                    result = self.pump(pattern, prev, i, result, timeout)
                    if result is not None:
                        status, pump = result
                        if status in pumping_groups:
                            pumping_groups[status].update(pump)
                        else:
                            pumping_groups[status] = REMultipattern([pump])
                            if first:
                                return pumping_groups
                prev = i
        return pumping_groups

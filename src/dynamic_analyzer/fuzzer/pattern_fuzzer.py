import re
from typing import List, Set, Dict, Tuple, Optional, Iterable

from src.const import (EXP_AMBIGUOUS, NO_AMBIGUOUS)
from src.dynamic_analyzer.ambiguity_analyzer import AmbiguityAnalyzer
from src.dynamic_analyzer.utils import (
    trim_last, trim_first, get_attack_postfix,
    check_intersection, get_overlapping, format_static)
from src.dynamic_analyzer.neightborhood.pattern_utils import (
    get_regex_first_k, get_regex_last_k, open_regex,
    get_n_neighborhood, get_zero_neighborhood)
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.dynamic_analyzer.const import PUMP_ID
from src.dynamic_analyzer.fuzzer.abstract_fuzzer import Fuzzer
from src.multipattern.repattern import REPattern, REVariable
from src.multipattern.recpattern import RECPattern
from src.multipattern.remultipattern import REMultipattern
from src.eregex.regex import Regex, ConcatenationRegex, BackrefRegex, BaseRegex
from src.wrappers.regex_matcher import RegexMatcher
from src.wrappers.static_analyzer import StaticAnalyzer


class REPatternFuzzer(Fuzzer):
    """Main structured fuzzing algorithm implementation for re-patterns"""

    def __init__(
        self,
        fuzzer: GeneticFuzzer,
        matcher: RegexMatcher,
        static_analyzer: StaticAnalyzer,
        ambiguity_analyzer: AmbiguityAnalyzer):
        super().__init__(matcher, static_analyzer, ambiguity_analyzer)
        self.genetic_fuzzer = fuzzer

    def _simplify_pattern(self, pattern: REPattern) -> REPattern:
        for elem in pattern.value:
            if isinstance(elem, REVariable) and isinstance(elem.regex, ConcatenationRegex):
                sub = [REVariable(v) if isinstance(v, Regex) else v for v in elem.regex.value]
                new_pattern = []
                for value in pattern.value:
                    if value == elem:
                        new_pattern += sub
                    else:
                        new_pattern.append(value)
                return self._simplify_pattern(REPattern(new_pattern))
        return pattern

    def _get_neighborhood(
        self,
        index: int,
        pattern: REPattern,
        k: int,
        n: int = 0) -> Set[str]:
        """Getting of left n-k-neighborhood

        Args:
            index (int): element index in the pattern.
            pattern (REPattern): context.
            k (int): string (neighborhood) length.
            n (int, optional): length of previous suffix == length current prefix. Defaults to 0.

        Returns:
            List[str]: n-k-neighborhood.
        """
        if n == 0:
            elem = pattern.value[index]
            if isinstance(elem, REVariable):
                return get_zero_neighborhood(elem.regex, k)
            else:
                result = get_regex_first_k(pattern.sub(index).get_regex(), k)
                return result[0].union(result[1])
            
        return get_n_neighborhood(
            pattern.sub(end = index).get_regex(),
            pattern.sub(start = index).get_regex(), n, k)
    
    def _pump_neighborhood(
        self,
        pattern: REPattern,
        start: int,
        end: int,
        radius_range: Iterable[int],
        top_k: int = 5) -> Optional[List[str]]:
        print("PUMP")
        if self.static_analyzer.analyze(pattern.sub(start, end + 1).get_regular_str()) == NO_AMBIGUOUS:
            return
        intersections = set()
        print("here")
        for k in radius_range:
            if pattern.value[start] != pattern.value[end]:
                x_1 = self._get_neighborhood(start, pattern, k)
                x_2 = self._get_neighborhood(end, pattern, k)
                print(f"x1 {pattern.sub(start, start + 1)}, k = {k}")
                print(x_1)

                print(f"x2 {pattern.sub(end, end + 1)}, k = {k}")
                print(x_2)
                if len(x_1) == 0 or len(x_2) == 0:
                    break
                cap = x_1.intersection(x_2)
            else:
                print(f"x1 {pattern.sub(start, start + 1)}, k = {k}")
                cap = self._get_neighborhood(start, pattern, k)
                print(cap)
            if len(cap) == 0:
                return
            if end - start > 1:
                for n in range(0, k // 2):
                    print("TRANS NEIGH")
                    trans = self._get_neighborhood(start + 1, pattern, k, n)
                    print(f"trans {n}")
                    print(trans)
                    trans_cap = cap.intersection(trans)
                    if len(trans_cap) == 0:
                        return
                    for tc in trans_cap:
                        if len(intersections) < top_k:
                            intersections.add(tc)
            else:
                for c in cap:
                    if len(intersections) < top_k:
                        intersections.add(c) 
        print("intersections")
        print(intersections)
        return sorted(intersections)
    
    def _pump_prefix(
        self,
        regex: str,
        w1: str, 
        w2: str, 
        iter_limit: int = 10) -> Optional[int]:
        print(f"prefix search {w1} {w2}")

        overlap = get_overlapping(w2, w1)
        if len(overlap) == 0:
            return
        for i in range(len(w1), 0, -1):
            count = len(overlap)
            flag = True
            if not self.matcher.match(w1[:i] * 2 + w1[i:], regex):
                continue
            for n in range(2, iter_limit):
                pump_w1 = w1[:i] * n + w1[i:]
                pump_w2 = w2 * n
                new_count = len(get_overlapping(pump_w2, pump_w1))
                if new_count <= count:
                    flag = False
                    break
            if flag:
                return i
    
    def _pump_suffix(
        self,
        regex: str,
        w1: str, 
        w2: str, 
        iter_limit: int = 10) -> Optional[int]:
        print(f"suffix search {w1} {w2}")

        overlap = get_overlapping(w1, w2)
        if len(overlap) == 0:
            return
        for i in range(len(w1)):
            count = len(overlap)
            flag = True
            if not self.matcher.match(w1[:i] + w1[i:] * 2, regex):
                continue
            for n in range(2, iter_limit):
                pump_w1 = w1[:i] + w1[i:] * n
                pump_w2 = w2 * n
                new_count = len(get_overlapping(pump_w1, pump_w2))
                if new_count <= count:
                    flag = False
                    break
            if flag:
                return i
    
    def _neighborhood_search(
        self,
        var: REVariable,
        inter: str,
        search_prefix: bool = False,
        iter_limit: int = 10,
        rec_limit: int = 5) -> Optional[Tuple[str, str]]:
        if search_prefix:
            for word in open_regex(var.regex, rec_limit):
                var.regex.delete_substitution()
                i = self._pump_prefix(str(var.regex), word, inter, iter_limit)
                if i is not None:
                    return word[:i], word[i:]
        else:
            for word in open_regex(var.regex, rec_limit):
                var.regex.delete_substitution()
                i = self._pump_suffix(str(var.regex), word, inter, iter_limit)
                if i is not None:
                    return word[:i], word[i:]
                
    def _genetic_search(
        self,
        var: REVariable,
        inter: str,
        search_prefix: bool = False,
        iter_limit: int = 10,
        num_epochs: int = 10) -> Optional[Tuple[str, str]]:

        def fitness_function(x, regex: str, search_prefix: bool = False) -> bool:
            if not match(x, regex):
                return False
            if search_prefix:
                i = self._pump_prefix(regex, x, inter, iter_limit)
            else:
                i = self._pump_suffix(regex, x, inter, iter_limit)
            return i is not None
        
        match = self.matcher.match
        regex = var.regex
        regex_str = str(regex)
        word = self.genetic_fuzzer.cast(
            {inter},
            [""] + trim_last(get_regex_first_k(regex, k=len(regex))) + \
            trim_first(get_regex_last_k(regex, k=len(regex))),
            lambda x: fitness_function(x, regex_str, search_prefix),
            num_epochs)
        if word is None:
            return
        
        if search_prefix:
            i = self._pump_prefix(regex_str, word, inter, iter_limit)
        else:
            i = self._pump_suffix(regex_str, word, inter, iter_limit)
        return word[:i], word[i:]
            
    def pump(
        self,
        pattern: REPattern,
        pattern_regex: Regex,
        start: int,
        end: int,
        intersection: List[str],
        timeout: float = 2,
        num_epochs: int = 10,
        rec_limit: int = 3,
        iter_range: List[int] = [1, 100, 10],
        genetic: bool = False,
        iter_limit: int = 10) -> Optional[Tuple[int, RECPattern]]:
        """Synchronous pumping

        Args:
            pattern (REPattern).
            start (int): index of the first variable.
            end (int): index of the last variable.
            intersection (List[str]): list of neighborhoods.
            timeout (float, optional): matching timeout. Defaults to 0.5.
            num_epochs (int, optional): number of epochs to evolve. Defaults to 10.
            rec_limit (int, optional): limit for opening regexes. Defaults to 3.
            iter_range (List[int], optional): range of pumping iterations. Defaults to [1, 100, 10].

        Returns:
            Optional[Tuple[int, REPattern]]: (ambiguity status, multipattern).
        """
        def format_word(
            inter: Tuple[str, str],
            target_subs: List[Tuple[str, str]],
            trans_subs: List[str],
            n: int = 2) -> str:
            # transition
            for var, sub in trans_subs.items():
                var.regex.substitute(sub)
            # target
            for i, var in enumerate(target_vars):
                sub = target_subs[var]
                # print("REGEX VALUE")
                # print(var.regex)
                var.regex.substitute(sub[0] + sub[1] * n if i == 0 else sub[0] * n + sub[1])
            # core
            core = inter[0] + inter[1] * (2 * n)
            attack = next(open_regex(pattern_regex.sub(end=start))) + core + postfix

            print("ATTACK")
            print(attack)
            print("-----------")

            pattern_regex.delete_substitution()
            # print(f"regex: {target_vars[0].regex.value}")
            # print(f"substitution: {target_vars[0].regex.substitution}")
            # print("DELETED")
            return attack
        
        def format_pattern(
            inter: Tuple[str, str],
            target_subs: List[Tuple[str, str]],
            trans_subs: List[str]) -> RECPattern:
            print("FORMAT")
            # transition
            for var, sub in trans_subs.items():
                var.regex.substitute(sub)
            # target
            vars = {}
            for i, var in enumerate(target_vars):
                sub = target_subs[var]
                name = f"[{PUMP_ID}{i}]"
                # print(f"regex: {var.regex.value}")
                # print(f"substitution: {var.regex.substitution}")
                var.regex.substitute(name)
                if sub[0] and sub[1]:
                    vars[name] = sub[0] + f"({sub[1]})*" if i == 0 else f"({sub[0]})*" + sub[1]
                else:
                    vars[name] = f"({sub[0] + sub[1]})*"
            # core
            c_name = "[" + PUMP_ID + "2]"
            vars[c_name] = inter[0] + f"({inter[1]})*"
            # print(pattern_regex.sub(end=start))
            attack_format = next(open_regex(pattern_regex.sub(end=start))) + c_name + \
                next(open_regex(pattern_regex.sub(start=end + 1))) + postfix
            pattern_regex.delete_substitution()
            return RECPattern(attack_format, vars)
  
        if pattern.value[start] != pattern.value[end]:
            target_vars = [pattern.value[start], pattern.value[end]]
        else:
            target_vars = [pattern.value[start]]
        trans_vars = [v for v in pattern.value[start + 1:end] if isinstance(v, REVariable)]
        ext_regex = str(pattern_regex)

        postfix = get_attack_postfix(pattern_regex)
        result = None
        for inter in intersection:
            print(f"inter {inter}")
            # target vars
            target_subs = {}
            for i, var in enumerate(target_vars):
                if genetic:
                    search_result = self._genetic_search(var, inter, i, iter_limit, num_epochs)
                else:
                    search_result = self._neighborhood_search(var, inter, i, iter_limit, rec_limit)
                if search_result is None:
                    target_subs = {}
                    break
                # print("SEARCH RES")
                # print(search_result)
                target_subs[var] = search_result
            if len(target_subs) == 0:
                continue
            
            # transition vars
            trans_subs = {}
            if len(trans_vars) > 0:
                double_inter = inter * 2
                traget_words = [
                    "".join(target_subs[target_vars[0]]),
                    "".join(target_subs[target_vars[-1]])]
                regex = pattern_regex.sub(start + 1, end)
                for word in open_regex(regex, rec_limit=len(inter)):
                    print(f"WORD: {word} for regex {regex}")
                    if double_inter.find(word) > -1 and \
                        get_overlapping(traget_words[0], word) and \
                            get_overlapping(word, traget_words[-1]):
                        for var in trans_vars:
                            trans_subs[var] = var.regex.substitution
                    regex.delete_substitution()
                if len(trans_subs) == 0:
                    continue
            
            first_sub = "".join(target_subs[target_vars[0]])
            inter_prefix = first_sub[:-len(get_overlapping(first_sub, inter))]
            result = [(inter_prefix, inter), target_subs, trans_subs]
            times, lens = [], []
            for k in range(*iter_range):
                word = format_word(*result, n=k)
                time = self.matcher.match_word(word, ext_regex, timeout)
                if time == timeout:
                    return EXP_AMBIGUOUS, format_pattern(*result)
                lens.append(len(word))
                times.append(time)
            amb = self.ambiguity_analyzer.analyze(times, lens)
            if amb > NO_AMBIGUOUS:
                return amb, format_pattern(*result)
        
    def _update_pumping_groups(
        self,
        pumping_groups: Dict[int, REMultipattern],
        value: Tuple[int, REPattern|REMultipattern]) -> None:
        status, pump = value
        if status in pumping_groups:
            if isinstance(pump, REMultipattern):
                pumping_groups[status].update(pump)
            else:
                pumping_groups[status].add(pump)
        else:
            if isinstance(pump, REMultipattern):
                pumping_groups[status] = pump
            else:
                pumping_groups[status] = REMultipattern([pump])

    def regex_to_pattern(self, regex: Regex) -> Optional[REPattern]:
        if isinstance(regex, BaseRegex):
            return REPattern([regex.value])
        elif isinstance(regex, ConcatenationRegex):
            pattern = []
            vars = {}
            for elem in regex.value:
                if isinstance(elem, BaseRegex):
                    pattern.append(str(elem))
                elif isinstance(elem, BackrefRegex):
                    pattern.append(vars[elem.regex_value])
                else:
                    pattern.append(REVariable(elem))
                    vars[elem] = pattern[-1]
            return REPattern(pattern)
    
    def run(
        self,
        regex: Regex,
        max_radius: int = 10,
        timeout: float = 2,
        rec_limit: int = 3,
        genetic: bool = False,
        first: bool = True) -> Dict[int, REMultipattern]:
        """Main loop for pattern analyzing

        Args:
            pattern (REPattern).
            max_radius (int, optional): max radius for neighborhood length. Defaults to 10.
            timeout (float, optional): matching timeout. Defaults to 0.5 sec.
            first (bool, optional): whether to get first ambiguity. Defaults to False.

        Returns:
            Dict[int, REMultipattern]: {ambiguity status: pumping multipattern}.
        """   
        # pattern = self._simplify_pattern(pattern)
        pattern = self.regex_to_pattern(regex)
        assert pattern is not None, "incorrect pattern"
        prevs = []
        pumping_groups = {}
        if self.static_analyzer.analyze(pattern.get_regular_str()) == NO_AMBIGUOUS:
            return pumping_groups
        print(pattern)
        for i, elem in enumerate(pattern.value):
            if isinstance(elem, REVariable):
                status = self.static_analyzer.analyze(str(elem.regex))
                if status > NO_AMBIGUOUS:
                    attack_pattern = format_static(regex, elem.regex, str(elem.regex))
                    # attack_pattern = make_attack_pattern(
                    #     pattern.sub(i).get_ext_regex(),
                    #     elem.regex,
                    #     get_attack_postfix(pattern.get_regex())
                    # )
                    self._update_pumping_groups(
                        pumping_groups,
                        (status, attack_pattern))
                    if first:
                        return pumping_groups
                if len(prevs) != 0:
                    if self.static_analyzer.analyze(pattern.sub(end=i + 1).get_regular_str()) == NO_AMBIGUOUS:
                        prevs.append(i)
                        continue
                    for prev in prevs:
                        print(f"PREV {pattern.value[prev]}")
                        if check_intersection(
                            prevs[prev + 1:],
                            [pattern.value[i], pattern.value[prev]]):
                            continue
                        trans_len = pattern.slice_len(prev + 1, i)
                        radius_range = range(max(1, trans_len), max_radius)
                        intersections = self._pump_neighborhood(pattern, prev, i, radius_range)
                        if intersections is None:
                            continue
                        attack = self.pump(
                            pattern,
                            regex,
                            prev, i,
                            intersections,
                            timeout=timeout,
                            genetic=genetic,
                            rec_limit=rec_limit)
                        if attack is not None:
                            self._update_pumping_groups(pumping_groups, attack)
                            if first:
                                return pumping_groups
                prevs.append(i)
        return pumping_groups

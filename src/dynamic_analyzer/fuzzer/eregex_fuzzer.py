from typing import (
    Any, List, Dict, Tuple, Iterator,
    Callable, Optional, Set, Iterable)
from copy import deepcopy
from itertools import combinations
import numpy as np

from src.const import (
    EMPTY, EXP_AMBIGUOUS, POLY_AMBIGUOUS,
    NO_AMBIGUOUS, SUBSTITUTION, CUTTION)
from src.dynamic_analyzer.utils import (
    get_generator, trim_first, trim_last, get_digit_prefix,
    invert_mask, check_regex_intersection, get_attack_postfix)
from src.dynamic_analyzer.neighborhood import (
    get_regex_first_k, get_regex_last_k, open_regex,
    get_n_neighborhood, get_zero_neighborhood)
from src.dynamic_analyzer.const import (NO, IN, OUT, ABOUT)
from src.dynamic_analyzer.fuzzer.abstract_fuzzer import Fuzzer
from src.multipattern.repattern import REPattern, REVariable
from src.multipattern.remultipattern import REMultipattern
from src.eregex.parser import ERegexParser
from src.eregex.abstract_regex import NodeRegex
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, AlternativeRegex,
    ConcatenationRegex, BackrefRegex, ext_to_classic)


class ERegexFuzzer(Fuzzer):
    """Main structured fuzzing algorithm implementation for e-regex"""

    def run(
        self,
        regex: Regex,
        max_radius: int = 10,
        timeout: float = 0.5,
        first: bool = True) -> Dict[int, REMultipattern]:
        """Main method for regex analyzing

        Args:
            regex_string (str).
            max_radius (int, optional): max radius for neighborhood length. Defaults to 10.
            timeout (float, optional): matching timeout. Defaults to 0.5 sec.
            first (bool, optional): whether to get first ambiguity. Defaults to False.

        Returns:
            Dict[int, REMultipattern]: {ambiguity status: pumping multipattern}.
        """
        regex = self._simplify_regex(regex)
        return self._process_regex(regex, max_radius, timeout, first)

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

    def _get_group_type(self, group: Regex, regex: Regex) -> int:
        outside = self._check_star_outside(group, regex)
        inside = self._is_finite(group)
        if outside and inside:
            return ABOUT
        if outside:
            return OUT
        if inside:
            return IN
        return NO
    
    def _get_backref_type(self, backref: BackrefRegex, regex: Regex) -> int:
        backref_type = OUT if self._check_star_outside(backref, regex) else NO
        group_type = self._get_group_type(backref.regex_value, regex)
        subs_type = [OUT, NO]
        if backref_type in subs_type and group_type in subs_type:
            return SUBSTITUTION
        return CUTTION
    
    def _check_node_inside(self, source: Regex, predicate: Callable) -> bool:
        if predicate(source):
            return True
        if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
            for value in source.value:
                if self._check_node_inside(value, predicate):
                    return True
        elif isinstance(source, StarRegex):
            return self._check_node_inside(source.value, predicate)
        return False
    
    def _get_backrefs(self, source: Regex) -> List[BackrefRegex]:
        if isinstance(source, BaseRegex):
            return []
        if isinstance(source, BackrefRegex):
            return [source]
        elif isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
            nodes = []
            for value in source.value:
                nodes += self._get_backrefs(value)
            return nodes
        return self._get_backrefs(source.value)

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

    def _is_group(self, regex: Regex, source: Regex) -> bool:
        if not regex.group:
            return False
        return self._check_node_inside(
            source, lambda x: isinstance(x, BackrefRegex) and x.regex_value == regex)
    
    def _is_finite(self, regex: Regex) -> bool:
        if isinstance(regex, BaseRegex):
            return True
        if isinstance(regex, BackrefRegex):
            return self._is_finite(regex.regex_value)
        if isinstance(regex, StarRegex):
            return False
        for value in regex.value:
            if self._is_finite(value):
                return True
        return False
    
    # TODO: remove if not needed
    def _find_parent(self, source: Regex, target: Regex) -> Optional[Regex]:
        if type(source) is not NodeRegex:
            return
        if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
            for value in source.value:
                if value == target:
                    return source
                parent = self._find_parent(value, target)
                if parent is not None:
                    return parent
        if source.value == target:
            return source
        return self._find_parent(source.value, target)
    
    # TODO: make function
    def _simplify_regex(self, main_regex: Regex) -> Regex:

        # def replace(self, source: Regex, target: Regex) -> Optional[Regex]:
        #     if type(source) is not NodeRegex:
        #         return
        #     if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
        #         for value in source.value:
        #             if value == target:
        #                 return source
        #             parent = self._find_parent(value, target)
        #             if parent is not None:
        #                 return parent
        #     if source.value == target:
        #         return source
        #     return self._find_parent(source.value, target)
            
        # def simplify(regex: Regex):
        #     new_regex = []
        #     if isinstance(regex, BaseRegex):
        #         return [BaseRegex]
        #     if isinstance(regex, StarRegex):
        #         return [StarRegex(simplify(regex.value))]
        #     if isinstance(regex, ConcatenationRegex):
        #         new_group = []
        #         if regex.group:
        #             for value in regex.value:
        #                 if isinstance(value, StarRegex):
        #                     value.group = True
        #                     new_group.append(value)
        #         for 
        #     if isinstance(regex, BackrefRegex):
        #         return self._is_finite(regex.regex_value)
        return main_regex
    
    def _get_neighborhood(
        self,
        index: int,
        case: ConcatenationRegex,
        k: int,
        n: int = 0) -> Set[str]:
        """Getting of left n-k-neighborhood

        Args:
            index (int): element index in the case.
            case (ConcatenationRegex): context.
            k (int): string (neighborhood) length.
            n (int, optional): length of previous suffix == length current prefix. Defaults to 0.

        Returns:
            List[str]: n-k-neighborhood.
        """
        if n == 0:
            return get_zero_neighborhood(case.value[index], k)
            
        return get_n_neighborhood(
            case.sub(end = index),
            case.sub(start = index), n, k)
    
    def _pump_neighborhood(
        self,
        case: ConcatenationRegex,
        start: int,
        end: int,
        radius_range: Iterable[int],
        top_k: int = 10) -> Optional[List[str]]:
        if self.static_analyzer(case.sub(start, end + 1).get_regular_str()) == NO_AMBIGUOUS:
            return
        intersections = set()
        for k in radius_range:
            x_1 = self._get_neighborhood(start, case, k)
            x_2 = self._get_neighborhood(end, case, k)
            if len(x_1) == 0 or len(x_2) == 0:
                break
            cap = x_1.intersection(x_2)
            if len(cap) == 0:
                return
            if end - start > 1:
                for n in range(1, k // 2):
                    trans = self._get_neighborhood(start + 1, case, k, n)
                    cap = cap.intersection(trans)
                    if len(cap) == 0:
                        return
            if len(intersections) < top_k:
                intersections.update(cap)
        return sorted(intersections)
    
    def pump(
        self,
        case: ConcatenationRegex,
        start: int,
        end: int,
        intersection: List[str],
        timeout: float = 0.5,
        num_epochs: int = 10,
        rec_limit: int = 3,
        max_iter: int = 30) -> Optional[Tuple[int, REPattern]]:
        """Synchronous pumping

        Args:
            pattern (REPattern).
            start (int): index of the first variable.
            end (int): index of the last variable.
            intersection (List[str]): list of neighborhoods.
            timeout (float, optional): matching timeout. Defaults to 0.5.
            num_epochs (int, optional): number of epochs to evolve. Defaults to 10.
            rec_limit (int, optional): limit for opening transition. Defaults to 3.
            max_iter (int, optional): max number of pumping iterations. Defaults to 30.

        Returns:
            Optional[Tuple[int, REPattern]]: (ambiguity status, multipattern).
        """
        def format_word(
            inter: str,
            subs: List[str],
            trans_subs: List[str],
            n: int = 2) -> str:
            # corners
            for i, word in enumerate(subs):
                target_vars[i].substitute(word)
            # transition
            for i, word in enumerate(trans_subs):
                trans_vars[i].substitute(word)
            # core
            attack = attack_format.replace("{2}", inter * (2 * n))
            return attack
        
        def format_regex(
            inter: str,
            subs: List[str],
            trans_subs: List[str]) -> REPattern:
            # make new variables
            target_regex_subs = []
            for word in subs:
                target_regex_subs.append(REVariable(ERegexParser(f"({word})*").parse()))
            target_regex_subs.append(REVariable(ERegexParser(f"({inter})*").parse()))
            # construst pattern
            i = 0
            pattern = []
            while i < len(attack_format):
                if attack_format[i] != "{" and attack_format[i] != "[":
                    pattern.append(attack_format[i])
                else:
                    id = get_digit_prefix(attack_format[i+1:])
                    pattern.append(target_regex_subs[id] if attack_format[i] == "{" else trans_subs[id])
                    i += len(id) + 1
                i += 1
            return REPattern(pattern)
  
        target_vars = [case.value[start], case.value[end]]
        trans_vars = [v for v in case.value[start + 1:end] if not isinstance(v, BaseRegex)]
        cast_trans = self._check_node_inside(
            case.sub(start + 1, end),
            lambda x: isinstance(x, BackrefRegex))
        postfix = get_attack_postfix(case)
        str_case = str(case)
        max_score = -1
        result = None
        for inter in intersection:
            # target vars
            target_subs = {}
            for var in target_vars:
                regex = var.regex
                regex_str = str(regex)
                target_subs[var] = self.fuzzer.cast(
                    [inter],
                    [""] + trim_last(get_regex_first_k(regex, k=len(var.regex))) + \
                    trim_first(get_regex_last_k(regex, k=len(var.regex))),
                    fitness_func = lambda x: self.matcher.match_word(x, regex_str),
                    num_epochs = num_epochs)
            
            # transition vars
            double_inter = inter * 2
            trans_subs = {var: [] for var in trans_vars}
            trans_count = 0
            if cast_trans:
                regex = case.sub(start + 1, end)
                for word in open_regex(regex, rec_limit=len(inter)):
                    if double_inter.find(word) > -1:
                        for var in vars:
                            trans_count += 1
                            trans_subs[var].append(var.regex.substitution)
                if trans_count == 0:
                    continue

            # attack casting
            for start_sub in target_subs[target_vars[0]]:
                for end_sub in target_subs[target_vars[1]]:
                    for trans_i in range(trans_count):
                        target_sub = [start_sub, end_sub]
                        trans_sub = [trans_subs[var][trans_i] for var in trans_vars]
                        word = format_word(inter, target_sub, trans_sub, n=2)
                        time = self.matcher.match_word(word, str_case, timeout)
                        score = time / len(word)
                        if score > max_score:
                            max_score = score
                            result = [inter, target_sub, trans_sub]
                    if not cast_trans:
                        target_sub = [start_sub, end_sub]
                        trans_sub = []
                        word = format_word(inter, target_sub, trans_sub, n=2)
                        time = self.matcher.match_word(word, str_case, timeout)
                        score = time / len(word)
                        if score > max_score:
                            max_score = score
                            result = [inter, target_sub, trans_sub]

        if result is None:
            return
        times, lens = [], []
        for k in range(1, max_iter):
            word = format_word(*result, n=k)
            lens.append(len(word))
            if time == timeout:
                return EXP_AMBIGUOUS, format_regex(*result)
            times.append(time)
        amb = self.ambiguity_analyzer.analyze(times, lens)
        if amb > NO_AMBIGUOUS:
            return amb, format_regex(*result)
    
    def _run_substitution(
        self,
        case: ConcatenationRegex,
        max_radius: int = 10,
        timeout: float = 0.8,
        first: bool = False) -> Dict[int, REMultipattern]:
        prevs = []
        pumping_groups = {}
        if self.static_analyzer(ext_to_classic(case)) == NO_AMBIGUOUS:
            return pumping_groups
        for i, elem in enumerate(case.value):
            if type(elem) is Regex:
                if self.static_analyzer(ext_to_classic(case.sub(end=i + 1))) == NO_AMBIGUOUS:
                    continue
                if len(prevs) != 0:
                    for prev in prevs:
                        if check_regex_intersection(
                            prevs[prev + 1:],
                            [case.value[i], case.value[prev]]):
                            continue
                        trans_len = len(case.sub(prev + 1, i))
                        radius_range = range(trans_len, trans_len + max_radius)
                        intersections = self._pump_neighborhood(case, prev, i, radius_range)
                        if intersections is None:
                            continue
                        attack = self.pump(case, prev, i, intersections, timeout)
                        if attack is not None:
                            self._update_pumping_groups(pumping_groups, attack)
                            if first:
                                return pumping_groups
                prevs.append(i)
        return pumping_groups
    
    def _process_substitutions(
        self,
        substitutions: List[Any],
        max_radius: int = 10,
        timeout: float = 0.5,
        first: bool = True) -> Dict[int, REMultipattern]:
        
        def get_substitution(substitution: List[Any]) -> Iterator[str|Regex]:
            if len(substitution) == 0:
                yield []
            first_sub = substitution[0]
            if isinstance(first_sub, List):
                for prefix in self._process_substitutions(first_sub):
                    for postfix in self._process_substitutions(substitution[1:]):
                        yield prefix + postfix
            elif isinstance(first_sub, Callable):
                first_sub = first_sub()
                for postfix in self._process_substitutions(substitution[1:]):
                    yield first_sub + postfix
            elif isinstance(first_sub, Iterator):
                for prefix in next(first_sub):
                    for postfix in self._process_substitutions(substitution[1:]):
                        yield first_sub + postfix
            else: # str or Regex
                for postfix in self._process_substitutions(substitution[1:]):
                    yield [first_sub] + postfix
        
        pumping_groups = {}
        for sub in get_substitution(substitutions):
            case = ConcatenationRegex(
                [BaseRegex(s) if isinstance(s, str) else s for s in sub])
            for item in self._run_substitution(case, max_radius, timeout, first).items():
                self._update_pumping_groups(pumping_groups, item)
        return pumping_groups
    
    def _process_regex(
        self,
        main_regex: Regex,
        max_radius: int = 10,
        timeout: float = 0.5,
        first: bool = True) -> Dict[int, REMultipattern]:
        pumping_groups = {}

        def check_group_inside(regex: Regex):
            return self._check_node_inside(
                regex, lambda x: self._is_group(x, main_regex))

        def check_backref_inside(regex: Regex):
            return self._check_node_inside(
                regex, lambda x: isinstance(x, BackrefRegex))

        def kleene_open(regex: StarRegex) -> List[Any]:
            star = deepcopy(regex)
            star.delete_group()
            base = regex.value
            cases = []
            for prefix in open_block(star):
                for suffix in open_block(base):
                    cases.append(prefix + suffix)
            return cases
        
        def subs_generator(regex: Regex) -> Iterator[List[str]]:
            if isinstance(regex, ConcatenationRegex):
                for prefix in open_block(regex.value[0]):
                    for suffix in open_block(regex.sub(start=1)):
                        result = prefix + suffix
                        regex.substitute(result)
                        yield result
            elif isinstance(regex, AlternativeRegex):
                for value in regex.value:
                    for result in open_block(value):
                        regex.substitute(result)
                        yield result
            regex.substitute(None)
        
        def open_block(regex: Regex) -> List[Any]:
            if isinstance(regex, BaseRegex):
                return [str(regex)]
            
            if isinstance(regex, StarRegex):
                # check exp situation
                value = regex.value
                if isinstance(value, ConcatenationRegex): 
                    if not self._is_finite(value):
                        double_iter = ConcatenationRegex(regex.value, regex.value)
                        result = self._process_regex(double_iter)
                        for status in [POLY_AMBIGUOUS, EXP_AMBIGUOUS]:
                            if status in result:
                                # TODO: patterns are incorrect - add prefix
                                self._update_pumping_groups(
                                    pumping_groups,
                                    (EXP_AMBIGUOUS, result[status]))
                                if first:
                                    return pumping_groups
                elif isinstance(value, AlternativeRegex):
                    values = np.array(value.value)
                    alt_len = len(values)
                    indexes = range(alt_len)
                    for k in range(alt_len // 2):
                        for mask in combinations(indexes, k):
                            alt_1 = AlternativeRegex(values[mask])
                            alt_2 = AlternativeRegex(values[invert_mask(mask, alt_len)])
                            double_alt = ConcatenationRegex(alt_1, alt_2)
                            result = self._process_regex(double_alt)
                            for status in [POLY_AMBIGUOUS, EXP_AMBIGUOUS]:
                                if status in result:
                                    # TODO: patterns are incorrect - add prefix
                                    self._update_pumping_groups( 
                                        pumping_groups,
                                        (EXP_AMBIGUOUS, result[status]))
                                    if first:
                                        return pumping_groups
                elif isinstance(value, StarRegex):
                    # make some pattern
                    if first:
                        return pumping_groups
                # constructing substitutions
                cases = [EMPTY]
                if self._is_group(regex, main_regex):
                    cases.append(regex)
                elif check_group_inside(regex):
                    cases += kleene_open(regex)
                elif check_backref_inside(regex):
                    # cases += open_block(regex.value)
                    cases.append(regex)
                else:
                    cases.append(regex)
                return cases
            
            if isinstance(regex, ConcatenationRegex):
                # check static parts
                static_regex = ""
                for value in regex.value:
                    if check_backref_inside(value):
                        if len(static_regex) > 0:
                            status = self.static_analyzer(static_regex)
                            if status > NO_AMBIGUOUS:
                                # TODO: make attack pattern
                                attack_pattern = REPattern([])
                                self._update_pumping_groups(
                                    pumping_groups,
                                    (status, attack_pattern))
                                if first:
                                    return pumping_groups
                        static_regex = ""
                    else:
                        static_regex += str(value)
                # constructing substitutions
                if self._is_group(regex, main_regex):
                    # another cases are simplified
                    return [get_generator(subs_generator, regex)]
                cases = [open_block(value) for value in regex.value]
                return cases
            
            if isinstance(regex, AlternativeRegex):
                # check static parts
                static_regex = ""
                for value in regex.value:
                    if not check_backref_inside(value):
                        static_regex += "|" + str(value)
                status = self.static_analyzer(static_regex)
                if status > NO_AMBIGUOUS:
                    # TODO: make attack pattern
                    attack_pattern = REPattern([])
                    self._update_pumping_groups(
                        pumping_groups,
                        (status, attack_pattern))
                    if first:
                        return pumping_groups
                # constructing substitutions
                if self._is_group(regex, main_regex):
                    if self._is_finite(regex):
                        return [get_generator(subs_generator, regex)]
                    return [regex]
                return [v for value in regex.value for v in open_block(value)]
            
            if isinstance(regex, BackrefRegex):
                if self._check_node_inside(main_regex, lambda x: x == regex.regex_value):
                    if self._get_backref_type(regex, main_regex) == SUBSTITUTION:
                        return [regex.regex_value.get_substitution]
                return [regex]

        attacks = self._process_substitutions(
            open_block(main_regex), max_radius, timeout, first)
        for item in attacks.items():
            self._update_pumping_groups(pumping_groups, item)
        return pumping_groups

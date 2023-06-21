from typing import (
    Any, List, Dict, Tuple, Iterator,
    Callable, Optional, Set, Iterable)
from itertools import combinations
import numpy as np
import re

from src.dynamic_analyzer.const import BASE_ID, PUMP_ID
from src.const import (
    EXP_AMBIGUOUS, NO_AMBIGUOUS, SUBSTITUTION, CUTTION)
from src.dynamic_analyzer.utils import (
    get_generator, invert_mask, key_generator,
    check_regex_intersection, get_attack_postfix,
    format_static, get_backrefs, format_nssnf,
    format_recattack, plot_dependance)
from src.dynamic_analyzer.neightborhood.eregex_utils import (
    open_regex, reopen_regex,
    get_n_neighborhood, get_zero_neighborhood,
    Path, update_storage, intersect_storages)

from src.dynamic_analyzer.const import (NO, IN, OUT, ABOUT)
from src.dynamic_analyzer.fuzzer.abstract_fuzzer import Fuzzer
from src.multipattern.recpattern import RECPattern
from src.multipattern.remultipattern import REMultipattern
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, AlternativeRegex,
    ConcatenationRegex, BackrefRegex, ext_to_classic,
    ordered, get_substitutions, deep_copy_regex, ordered)


class ERegexFuzzer(Fuzzer):
    """Main structured fuzzing algorithm implementation for e-regex"""

    def run(
        self,
        regex: Regex,
        max_radius: int = 10,
        timeout: float = 2,
        rec_limit: int = 3,
        visualize: bool = False,
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
        self.key_generator = key_generator()
        regex = self._simplify_regex(regex)
        return self._process_regex(
            regex,
            max_radius=max_radius,
            timeout=timeout,
            first=first,
            visualize=visualize,
            rec_limit=rec_limit)

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
        inside = not self._is_finite(group)
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

    def _update_pumping_groups(
        self,
        pumping_groups: Dict[int, REMultipattern],
        value: Tuple[int, RECPattern|REMultipattern]) -> None:
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
            if not self._is_finite(value):
                return False
        return True
    
    def _simplify_regex(self, main_regex: Regex) -> Regex:

        def replace(regex: Regex, target: Regex, replacement: ConcatenationRegex):
            if isinstance(regex, BaseRegex) or isinstance(regex, BackrefRegex):
                return
            if isinstance(regex, ConcatenationRegex) or isinstance(regex, AlternativeRegex):
                for i, value in enumerate(regex.value):
                    if isinstance(value, BackrefRegex) and value.regex_value == target:
                        regex.value[i] = replacement
                    else:
                        replace(value, target, replacement)
            else: # StarRegex
                value = regex.value
                if isinstance(value, BackrefRegex) and value.regex_value == target:
                    regex.value = replacement
                else:
                    replace(value, target, replacement)

        def flatten(regex: Regex):
            if isinstance(regex, ConcatenationRegex):
                regex.unpack()
                for value in regex.value:
                    flatten(value)
            elif isinstance(regex, AlternativeRegex):
                for value in regex.value:
                    flatten(value)
            elif isinstance(regex, StarRegex):
                flatten(regex.value)
            
        def simplify(regex: Regex, directly: bool = False) -> bool:
            if isinstance(regex, BaseRegex) or isinstance(regex, BackrefRegex):
                return False
            if isinstance(regex, StarRegex):
                return simplify(regex.value, regex.value.group)
            if isinstance(regex, ConcatenationRegex):
                if regex.group and not directly:
                    replacement = []
                    for value in regex.value:
                        if isinstance(value, BaseRegex):
                            replacement.append(value)
                        else:
                            value.group = True
                            replacement.append(BackrefRegex("", value))
                    replacement = ConcatenationRegex(replacement)
                    replace(main_regex, regex, replacement)
                    regex.group = False
                    return True
            is_simplified = False
            for value in regex.value:
                if simplify(value):
                    is_simplified = True
            return is_simplified
            
        while simplify(main_regex):
            continue
        flatten(main_regex)
        ordered(main_regex)
        return main_regex
    
    def _get_neighborhood(
        self,
        index: int,
        case: ConcatenationRegex,
        k: int,
        n: int = 0,
        is_var: bool = True) -> Dict[str, Set[Path]]:
        """Getting of left n-k-neighborhood

        Args:
            index (int): element index in the case.
            case (ConcatenationRegex): context.
            k (int): string (neighborhood) length.
            n (int, optional): length of previous suffix == length current prefix. Defaults to 0.

        Returns:
            List[str]: n-k-neighborhood.
        """
        if is_var and n == 0:
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
        top_k: int = 5) -> Optional[Dict[str, Set[Path]]]:
        def is_one_variable(r1: Regex, r2: Regex) -> bool:
            if isinstance(r1, BackrefRegex):
                if isinstance(r2, BackrefRegex) and r2.regex_value == r1.regex_value:
                    return True
                if r1.regex_value == r2:
                    return True
            if isinstance(r2, BackrefRegex) and r2.regex_value == r1:
                return True
            return False

        intersections = {}
        for k in radius_range:
            if not is_one_variable(case.value[start], case.value[end]):
                x_1 = self._get_neighborhood(start, case, k)
                x_2 = self._get_neighborhood(end, case, k)
                if len(x_1.keys()) == 0 or len(x_2.keys()) == 0:
                    break
                cap = intersect_storages(x_1, x_2)
            else:
                cap = self._get_neighborhood(start, case, k)
            if len(cap) == 0:
                return
            if end - start > 1:
                for n in range(0, k // 2):
                    trans = self._get_neighborhood(start + 1, case, k, n, is_var=False)
                    trans_cap = {word: paths for word, paths in cap.items() if word in trans}
                    if len(trans_cap) == 0:
                        return
                    if len(intersections) < top_k:
                        update_storage(intersections, trans_cap)
            else:
                if len(intersections) < top_k:
                    update_storage(intersections, cap)
        return intersections
    
    def pump(
        self,
        case: ConcatenationRegex,
        start: int,
        end: int,
        intersection: Dict[str, Set[Path]],
        timeout: float = 2,
        rec_limit: int = 3,
        visualize: bool = False,
        iter_range: List[int] = [1, 150, 10]) -> Optional[Tuple[int, Tuple]]:
        """Synchronous pumping

        Args:
            case (ConcatenationRegex).
            start (int): index of the first variable.
            end (int): index of the last variable.
            intersection (Dict[str, Set[Path]]): list of neighborhoods.
            timeout (float, optional): matching timeout. Defaults to 0.5.
            rec_limit (int, optional): limit for opening transition. Defaults to 3.
            iter_range (List[int], optional): range of pumping iterations. Defaults to [1, 100, 10].

        Returns:
            Optional[Tuple[int, REPattern]]: (ambiguity status, multipattern).
        """
        def format_word(
            inter: str,
            target_subs: Dict[Regex, str],
            trans_subs: Dict[Regex, str],
            n: int = 2) -> str:
            for var, sub in trans_subs.items():
                var.substitute(sub)
            
            first_sub = target_subs[target_vars[0]]
            f_idx = first_sub.find(inter)
            target_vars[0].substitute(first_sub[:f_idx] + first_sub[f_idx:] * n)

            if target_vars[-1] != target_vars[0]:
                last_sub = target_subs[target_vars[-1]]
                l_idx = last_sub.find(inter) + len(inter)
                target_vars[1].substitute(last_sub[:l_idx] * n + last_sub[l_idx:])

            core = first_sub[:f_idx] + inter * (2 * n)
            sub_regex = case.sub(end=start)
            attack = next(open_regex(sub_regex)) + core + postfix
            return attack
        
        def format_pattern(
            inter: str,
            target_subs: Dict[Regex, str],
            trans_subs: Dict[Regex, str]) -> Tuple[RECPattern, Dict[Regex, str]]:
            for var, sub in trans_subs.items():
                var.substitute(sub)
            # first var
            vars = {}
            first_sub = target_subs[target_vars[0]]
            f_idx = first_sub.find(inter)
            if isinstance(target_vars[0], BackrefRegex):
                f_name = "[" + target_vars[0].value.replace("\\", BASE_ID) + "]"
            else:
                f_name = "[" + PUMP_ID + next(self.key_generator) + "]"
            target_vars[0].substitute(f_name)
            vars[f_name] = RECPattern(first_sub[:f_idx] + f"({first_sub[f_idx:]})*")
            # last var
            if target_vars[-1] != target_vars[0]:
                last_sub = target_subs[target_vars[-1]]
                l_idx = last_sub.find(inter) + len(inter)
                if isinstance(target_vars[0], BackrefRegex):
                    l_name = "[" + target_vars[0].value.replace("\\", BASE_ID)  + "]"
                else:
                    l_name = "[" + PUMP_ID + next(self.key_generator)  + "]"
                target_vars[1].substitute(l_name)
                vars[l_name] = RECPattern(f"({last_sub[:l_idx]})*" + last_sub[l_idx:])
            # core
            c_name = "[" + PUMP_ID + next(self.key_generator)  + "]"
            vars[c_name] = RECPattern(first_sub[:f_idx] + f"({inter})*")
            attack = next(open_regex(case.sub(end=start))) + c_name + \
                next(open_regex(case.sub(start=end + 1))) + postfix
            history = get_substitutions(case)
            case.delete_substitution()
            if not all([re.sub("[^A-z]", "", pat.value) == "" for pat in vars.values()]):
                return RECPattern(attack, vars, history)
  
        target_vars = [case.value[start], case.value[end]]
        trans_vars = [b for b in get_backrefs(case.sub(start, end + 1)) if b not in target_vars]
        trans_vars += [b.regex_value for b in trans_vars]
    
        case.delete_substitution()
        postfix = get_attack_postfix(case)
        regex = case.sub(start, end + 1)
        max_score = -1
        result = None
        # substitutions casting
        for inter, memory in intersection.items():
            for path in memory:

                for word in reopen_regex(regex, path.value, rec_limit):
                    trans_subs = {var: var.substitution for var in trans_vars}
                    target_subs = {var: var.substitution for var in target_vars}
                    ordered(case)
                    word = format_word(inter, target_subs, trans_subs, n=2)
                    time = self.matcher.match_word(word, case.get_value_str(), timeout)
                    if time == timeout:
                        pattern = format_pattern(inter, target_subs, trans_subs)
                        if pattern is not None:
                            return EXP_AMBIGUOUS, pattern
                    score = time / len(word)
                    if score > max_score:
                        max_score = score
                        result = [inter, target_subs, trans_subs]

        case.delete_substitution()
        str_case = None
        if result is None:
            return
        times, lens = [], []
        for k in range(*iter_range):
            word = format_word(*result, n=k)
            if str_case is None:
                ordered(case)
                str_case = case.get_value_str() 
            time = self.matcher.match_word(word, str_case, timeout)
            if time == timeout:
                pattern = format_pattern(*result)
                if pattern is None:
                    return EXP_AMBIGUOUS, pattern
                return EXP_AMBIGUOUS, pattern
            lens.append(len(word))
            times.append(time)
        amb = self.ambiguity_analyzer.analyze(times, lens)
        pattern = format_pattern(*result)
        if pattern is not None:
            if visualize:
                plot_dependance(times, lens, str_case + "\n" + pattern.value)
            if amb > NO_AMBIGUOUS:
                return amb, pattern
    
    def _run_substitution(
        self,
        case: ConcatenationRegex,
        max_radius: int = 4,
        rec_limit: int = 3,
        visualize: bool = False,
        iter_range: List[int] = [1, 150, 10],
        timeout: float = 2,
        first: bool = False) -> Dict[int, Tuple]:
        prevs = []
        pumping_groups = {}
        if self.static_analyzer.analyze(ext_to_classic(case)) == NO_AMBIGUOUS:
            return pumping_groups
        for i, elem in enumerate(case.value):
            if not isinstance(elem, BaseRegex):
                if self.static_analyzer.analyze(ext_to_classic(case.sub(end=i + 1))) == NO_AMBIGUOUS:
                    prevs.append(i)
                    continue
                if len(prevs) != 0:
                    for prev in prevs:
                        if check_regex_intersection(
                            prevs[prev + 1:],
                            [case.value[i], case.value[prev]]):
                            continue
                        trans_len = len(case.sub(prev + 1, i))
                        radius_range = range(min(1, trans_len), max_radius)
                        intersections = self._pump_neighborhood(case, prev, i, radius_range)
                        if intersections is None:
                            continue
                        attack = self.pump(
                            case,
                            prev, i,
                            intersections,
                            timeout=timeout,
                            rec_limit=rec_limit,
                            visualize=visualize,
                            iter_range=iter_range)
                        if attack is not None:
                            self._update_pumping_groups(pumping_groups, attack)
                            if first:
                                return pumping_groups
                prevs.append(i)
        return pumping_groups
    
    def _process_substitutions(
        self,
        substitutions: Iterable,
        max_radius: int = 10,
        rec_limit: int = 3,
        visualize: bool = False,
        timeout: float = 2,
        first: bool = True) -> Dict[int, Tuple]:
        
        def get_substitution(substitution: Any) -> Iterator[List[str|Regex]]:
            if isinstance(substitution, Tuple):
                if len(substitution) == 0:
                    yield []
                else:
                    for sub in substitution:
                        for word in get_substitution(sub):
                            yield word
            elif isinstance(substitution, List):
                if len(substitution) == 0:
                    yield []
                elif len(substitution) == 1:
                    for prefix in get_substitution(substitution[0]):
                        yield prefix
                else:
                    for prefix in get_substitution(substitution[0]):
                        for postfix in get_substitution(substitution[1:]):
                            yield prefix + postfix
            elif isinstance(substitution, Callable):
                word = substitution()
                yield ["" if word is None else word]
            elif isinstance(substitution, Iterator):
                for word in next(substitution):
                    yield [word]
            else: # str or Regex
                yield [substitution]
        
        pumping_groups = {}
        for sub in get_substitution(substitutions):
            case = ConcatenationRegex(
                [BaseRegex(s) if isinstance(s, str) else s for s in sub])
            for item in self._run_substitution(
                case=case,
                max_radius=max_radius,
                rec_limit=rec_limit,
                timeout=timeout,
                visualize=visualize,
                first=first).items():
                self._update_pumping_groups(pumping_groups, item)
        return pumping_groups
    
    def _process_regex(
        self,
        main_regex: Regex,
        max_radius: int = 10,
        rec_limit: int = 3,
        visualize: bool = False,
        timeout: float = 2,
        first: bool = True) -> Dict[int, REMultipattern]:
        pumping_groups = {}
        return_flag = False

        def check_group_inside(regex: Regex):
            return self._check_node_inside(
                regex, lambda x: self._is_group(x, main_regex))

        def check_backref_inside(regex: Regex):
            return self._check_node_inside(
                regex, lambda x: isinstance(x, BackrefRegex))

        def kleene_open(regex: StarRegex) -> List[Any]:
            star = deep_copy_regex(regex)
            cases = [star, open_block(regex.value)]
            return cases

        def process_static(regex: Regex, static_regex: str) -> bool:
            nonlocal return_flag
            flag = False
            status = self.static_analyzer.analyze(static_regex)
            if status > NO_AMBIGUOUS:
                flag = True
                attack_pattern = format_static(
                    main_regex, regex, static_regex, self.key_generator)
                self._update_pumping_groups(
                    pumping_groups,
                    (status, attack_pattern))
                if first:
                    return_flag = True
            return flag
        
        def open_block(regex: Regex) -> Iterable:
            nonlocal return_flag
            if isinstance(regex, BaseRegex):
                return [str(regex)]
            
            if isinstance(regex, StarRegex):
                # check static
                if not check_backref_inside(regex):
                    if process_static(regex, str(regex)):
                        return_flag = True
                    if return_flag:
                        return []
                # check exp situation
                value = regex.value
                if isinstance(value, ConcatenationRegex):
                    if len(value) == 1:
                        value = value.value[0]
                    else:
                        if not self._is_finite(value):
                            double_iter = ConcatenationRegex([regex.value, regex.value])
                            for pattern in self._process_regex(double_iter).values():
                                pattern.apply(lambda x: 
                                    format_recattack(main_regex, regex, x, self.key_generator))
                                self._update_pumping_groups(
                                    pumping_groups,
                                    (EXP_AMBIGUOUS, pattern))
                                if return_flag:
                                    return []
                if isinstance(value, AlternativeRegex):
                    values = np.array(value.value)
                    alt_len = len(values)
                    indexes = range(alt_len)
                    for k in range(1, alt_len // 2 + 1): 
                        for mask in combinations(indexes, k):
                            mask = list(mask)
                            alt_1 = StarRegex(AlternativeRegex(values[mask]) 
                                if len(values[mask]) > 1 else values[mask][0])
                            inverse_mask = invert_mask(mask, alt_len)
                            alt_2 = StarRegex(AlternativeRegex(values[inverse_mask])
                                if len(values[inverse_mask]) > 1 else values[inverse_mask][0])
                            double_alt = ConcatenationRegex([alt_1, alt_2])
                            for pattern in self._process_regex(double_alt).values():
                                pattern.apply(lambda x: 
                                    format_recattack(main_regex, regex, x, self.key_generator))
                                self._update_pumping_groups(
                                    pumping_groups,
                                    (EXP_AMBIGUOUS, pattern))
                                if first:
                                    return_flag = True
                                    return []
                if isinstance(value, StarRegex):    
                    attack_pattern = format_nssnf(main_regex, regex, value, self.key_generator)
                    self._update_pumping_groups( 
                        pumping_groups,
                        (EXP_AMBIGUOUS, attack_pattern))
                    if first:
                        return_flag = True
                        return []
                # constructing substitutions          
                cases = []
                if check_group_inside(regex.value):
                    
                    cases.append(regex)
                    cases.append(kleene_open(regex))
                elif check_backref_inside(regex):
                    cases.append(open_block(regex.value))
                    cases.append(regex)
                else:
                    cases.append(regex)
                return tuple(cases)
            
            if isinstance(regex, ConcatenationRegex):
                # check static parts
                static_regex = ""
                for value in regex.value:
                    if check_backref_inside(value):
                        if len(static_regex) > 0:
                            process_static(regex, static_regex)
                            if return_flag:
                                return []
                            static_regex = ""
                    else:
                        static_regex += str(value)
                if len(static_regex) > 0:
                    process_static(regex, static_regex)
                    if return_flag:
                        return []
                # constructing substitutions
                if self._is_group(regex, main_regex):
                    # another cases are simplified
                    return [get_generator(open_regex, regex)]
                
                return [open_block(value) for value in regex.value]
            
            if isinstance(regex, AlternativeRegex):             
                # check static parts
                static_regex = ""
                for value in regex.value:
                    if not check_backref_inside(value):
                        static_regex += "|" + str(value)
                process_static(regex, static_regex)
                if return_flag:
                    return []
                # constructing substitutions
                if self._is_group(regex, main_regex):
                    if self._is_finite(regex):
                        return [get_generator(open_regex, regex)]
                    return [regex]
                return (v for value in regex.value for v in open_block(value))
            
            if isinstance(regex, BackrefRegex): 
                if self._check_node_inside(main_regex, lambda x: x == regex.regex_value):
                    if self._get_backref_type(regex, main_regex) == SUBSTITUTION:
                        return [regex.regex_value.get_substitution]
                return [regex]

        block_value = open_block(main_regex)
        if return_flag:
            return pumping_groups
        attacks = self._process_substitutions(
            block_value,
            max_radius=max_radius,
            timeout=timeout,
            first=first,
            visualize=visualize,
            rec_limit=rec_limit)
        for item in attacks.items():
            self._update_pumping_groups(pumping_groups, item)
        return pumping_groups

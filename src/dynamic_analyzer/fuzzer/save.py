from typing import (
    Any, List, Dict, Tuple, Iterator,
    Callable, Optional, Set, Iterable)
from itertools import combinations
import numpy as np

from src.dynamic_analyzer.const import BASE_ID, PUMP_ID
from src.const import (
    EMPTY, EXP_AMBIGUOUS, NO_AMBIGUOUS, SUBSTITUTION, CUTTION)
from src.dynamic_analyzer.utils import (
    get_generator, invert_mask, key_generator,
    check_regex_intersection, get_attack_postfix,
    format_static, get_backrefs, format_nssnf,
    format_recattack)
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
        timeout: float = 0.5,
        rec_limit: int = 3,
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
        print(f"BEFORE SIMPLIFIED {regex}")
        regex = self._simplify_regex(regex)
        print(f"SIMPLIFIED {regex}")
        return self._process_regex(
            regex,
            max_radius=max_radius,
            timeout=timeout,
            first=first,
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
        print(f"subs type {subs_type}")
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

    # def _update_pumping_groups(
    #     self,
    #     pumping_groups: Dict[int, REMultipattern],
    #     value: Tuple[int, RECPattern|REMultipattern]) -> None:
    #     status, pump = value
    #     if status in pumping_groups:
    #         pumping_groups[status].append(pump)
    #     else:
    #         pumping_groups[status] = [pump]

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
                return simplify(regex.value, regex.value.group) # False # simplify(regex.value)
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
        main_regex.plot().render("visualization/image.gv", format="png")
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

        print(f"PUMP NEIGHBORHOOD {case.value[start]} to {case.value[end]}")
        intersections = {}
        radius_range = range(1, 4)
        for k in radius_range:
            if not is_one_variable(case.value[start], case.value[end]):
                x_1 = self._get_neighborhood(start, case, k)
                x_2 = self._get_neighborhood(end, case, k)
                # print(f"x1 : {[(k, str(vv.value)) for k, v in x_1.items() for vv in v]}")
                # print(f"x2: {x_2}")
                if len(x_1.keys()) == 0 or len(x_2.keys()) == 0:
                    break
                cap = intersect_storages(x_1, x_2)
            else:
                cap = self._get_neighborhood(start, case, k)
            # print(f"regex {case.value[start]} k = {k}")
            # print(f"CAP: {cap}")
            if len(cap) == 0:
                return
            if end - start > 1:
                for n in range(0, k // 2):
                    # print("to TRANS")
                    trans = self._get_neighborhood(start + 1, case, k, n, is_var=False)
                    # print(f"CAP: {cap}")
                    # print(f"trans: {trans}")
                    # print()
                    trans_cap = {word: paths for word, paths in cap.items() if word in trans} # intersect_storages(cap, trans)
                    # print(f"trans cap {trans_cap}")
                    if len(trans_cap) == 0:
                        return
                    if len(intersections) < top_k:
                        update_storage(intersections, trans_cap)
            else:
                if len(intersections) < top_k:
                    update_storage(intersections, cap)
        print("intersections")
        print(intersections.keys())
        return intersections
    
    def pump(
        self,
        case: ConcatenationRegex,
        start: int,
        end: int,
        intersection: Dict[str, Set[Path]],
        timeout: float = 2,
        rec_limit: int = 3,
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
            print("FIRST_SUB")
            print(first_sub)
            vars[f_name] = RECPattern(first_sub[:f_idx] + f"({first_sub[f_idx:]})*")

            # last var
            if target_vars[-1] != target_vars[0]:
                last_sub = target_subs[target_vars[-1]]
                print("LAST_SUB")
                print(last_sub)
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
            print("REC_PATTERN")
            print(RECPattern(attack, vars, history))
            return RECPattern(attack, vars, history)
  
        target_vars = [case.value[start], case.value[end]]
        trans_vars = [b for b in get_backrefs(case.sub(start, end + 1)) if b not in target_vars]
        trans_vars += [b.regex_value for b in trans_vars]
    
        case.delete_substitution()
        postfix = get_attack_postfix(case)
        regex = case.sub(start, end + 1)
        ordered(case)
        str_case = str(case)
        max_score = -1
        result = None

        # substitutions casting
        for inter, memory in intersection.items():
            for path in memory:
                # print(f"PATH: {inter}")
                # print(target_vars[0], target_vars[1])
                # print(target_vars[0] in path.value.keys())
                # print(target_vars[1] in path.value.keys())
                # print(path)

                for word in reopen_regex(regex, path.value, rec_limit):
                    print("OPEN")
                    print(f"reopen_regex {regex.value}")
                    trans_subs = {var: var.substitution for var in trans_vars}
                    target_subs = {var: var.substitution for var in target_vars}
                    # print("TARGET SUBS")
                    # print(target_subs)
                    word = format_word(inter, target_subs, trans_subs, n=2)
                    time = self.matcher.match_word(word, str_case, timeout)
                    if time == timeout:
                        return EXP_AMBIGUOUS, format_pattern(inter, target_subs, trans_subs)
                    score = time / len(word)
                    if score > max_score:
                        max_score = score
                        result = [inter, target_subs, trans_subs]
        case.delete_substitution()
        print(f"CASE AFTER DELETE: {case}")
        if result is None:
            return
        times, lens = [], []
        for k in range(*iter_range):
            word = format_word(*result, n=k)
            # print(str_case)
            # print(word)
            time = self.matcher.match_word(word, str_case, timeout)
            if time == timeout:
                return EXP_AMBIGUOUS, format_pattern(*result)
            lens.append(len(word))
            times.append(time)
        amb = self.ambiguity_analyzer.analyze(times, lens)
        if amb > NO_AMBIGUOUS:
            return amb, format_pattern(*result)
    
    def _run_substitution(
        self,
        case: ConcatenationRegex,
        max_radius: int = 10,
        rec_limit: int = 3,
        timeout: float = 0.8,
        first: bool = False) -> Dict[int, Tuple]:
        print(f"START RUN {case}")

        prevs = []
        pumping_groups = {}
        if self.static_analyzer.analyze(ext_to_classic(case)) == NO_AMBIGUOUS:
            return pumping_groups
        for i, elem in enumerate(case.value):
            print(f"ELEM {elem}")
            print(f"PREVS {prevs}")
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
                        radius_range = range(max(1, trans_len), max_radius)
                        intersections = self._pump_neighborhood(case, prev, i, radius_range)
                        if intersections is None:
                            continue
                        attack = self.pump(case, prev, i, intersections, timeout, rec_limit)
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
        timeout: float = 0.5,
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
                yield [substitution()]
            elif isinstance(substitution, Iterator):
                print("Iterator")
                print(f"substitution {substitution}")
                for word in next(substitution):
                    yield [word]
            else: # str or Regex
                yield [substitution]
        
        pumping_groups = {}
        for sub in get_substitution(substitutions):
            print(f"SUBSTITUTION: {sub}")
            print(sub[-1])
            case = ConcatenationRegex(
                [BaseRegex(s) if isinstance(s, str) else s for s in sub])
            for item in self._run_substitution(case, max_radius, rec_limit, timeout, first).items():
                self._update_pumping_groups(pumping_groups, item)
        return pumping_groups
    
    def _process_regex(
        self,
        main_regex: Regex,
        max_radius: int = 10,
        rec_limit: int = 3,
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
        
        def subs_generator(regex: Regex) -> Iterator[List[str]]:
            if isinstance(regex, ConcatenationRegex):
                if len(regex.value) == 1:
                    for result in open_block(regex.value[0]):
                        regex.substitute(result)
                        yield result
                else:
                    for prefix in open_block(regex.value[0]):
                        for suffix in open_block(regex.sub(start=1)):
                            print(f"PREFIX({regex.value[0]}) + SUFFIX({regex.sub(start=1)})")
                            print(prefix, suffix)
                            result = prefix + suffix
                            regex.substitute(result)
                            yield result
            elif isinstance(regex, AlternativeRegex):
                for value in regex.value:
                    for result in open_block(value):
                        regex.substitute(result)
                        yield result
            # elif isinstance(regex, StarRegex):
            #     for result in open_block(regex.value):
            #         regex.substitute(result)
            #         yield result
            regex.substitute(None)

        def process_static(regex: Regex, static_regex: str):
            nonlocal return_flag
            status = self.static_analyzer.analyze(static_regex)
            if status > NO_AMBIGUOUS:
                attack_pattern = format_static(
                    main_regex, regex, static_regex, self.key_generator)
                self._update_pumping_groups(
                    pumping_groups,
                    (status, attack_pattern))
                if first:
                    return_flag = True
        
        def open_block(regex: Regex) -> Iterable:
            nonlocal return_flag
            if isinstance(regex, BaseRegex):
                return [str(regex)]
            
            if isinstance(regex, StarRegex):
                print(f"STAR {regex}")
                # check static
                if not check_backref_inside(regex):
                    process_static(regex, str(regex))
                    if return_flag:
                        return []
                    return [regex]
                
                # check exp situation
                value = regex.value
                if isinstance(value, ConcatenationRegex):
                    print(f"CONC STAR {value}")
                    if len(value) == 1:
                        value = value.value[0]
                    else:
                        print(f"value {value}")
                        if not self._is_finite(value):
                            print("DOUBLE ITER")
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
                    print(f"ALT STAR {value}")
                    values = np.array(value.value)
                    alt_len = len(values)
                    indexes = range(alt_len)
                    for k in range(1, alt_len // 2 + 1):
                        print(f"K = {k} from {len(indexes)}")
                        for mask in combinations(indexes, k):
                            mask = list(mask)
                            print(f"mask {mask}")
                            alt_1 = StarRegex(AlternativeRegex(values[mask]) 
                                if len(mask) > 1 else values[mask[0]])
                            inverse_mask = invert_mask(mask, alt_len)
                            alt_2 = StarRegex(AlternativeRegex(values[inverse_mask])
                                if len(inverse_mask) > 1 else values[inverse_mask[0]])
                            double_alt = ConcatenationRegex([alt_1, alt_2])
                            print("DOUBLE ALT")
                            print(double_alt)
                            double_alt.plot().render(f"visualization/double_{mask[0]}.gv", format="png")
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
                    print(f"STAR STAR {value}")
                    attack_pattern = format_nssnf(main_regex, regex, value, self.key_generator)
                    self._update_pumping_groups( 
                        pumping_groups,
                        (EXP_AMBIGUOUS, attack_pattern))
                    if first:
                        return_flag = True
                        return []
                # constructing substitutions
                print(f"STAR {regex}")
                cases = [EMPTY]
                if check_group_inside(regex):
                    print("KLEEEEENE")
                    cases.append(kleene_open(regex))
                elif check_backref_inside(regex):
                    cases.append(open_block(regex.value))
                    cases.append(regex)
                else:
                    cases.append(regex)
                print("CASES")
                print(cases)
                return tuple(cases)
            
            if isinstance(regex, ConcatenationRegex):
                print(f"CONC {regex}")
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
                    return [get_generator(subs_generator, regex)]
                print(f"HERE {regex}")
                return [open_block(value) for value in regex.value]
            
            if isinstance(regex, AlternativeRegex):
                print(f"ALT {regex}")
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
                        return [get_generator(subs_generator, regex)]
                    return [regex]
                return (v for value in regex.value for v in open_block(value))
            
            if isinstance(regex, BackrefRegex):
                print(f"REF {regex}")
                if self._check_node_inside(main_regex, lambda x: x == regex.regex_value):
                    if self._get_backref_type(regex, main_regex) == SUBSTITUTION:
                        return [regex.regex_value.get_substitution]
                return [regex]

        print("main_regex")
        print(main_regex)
        block_value = open_block(main_regex)
        print(f"BLOCK value {block_value}")
        if return_flag:
            return pumping_groups
        attacks = self._process_substitutions(
            block_value,
            max_radius=max_radius,
            timeout=timeout,
            first=first,
            rec_limit=rec_limit)
        for item in attacks.items():
            self._update_pumping_groups(pumping_groups, item)
        return pumping_groups
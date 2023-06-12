from typing import List, Set, Dict, Tuple, Optional, Iterable

from src.const import (EXP_AMBIGUOUS, NO_AMBIGUOUS)
from src.dynamic_analyzer.utils import (
    trim_last, trim_first, get_digit_prefix,
    make_attack_pattern, get_attack_postfix,
    check_intersection)
from src.dynamic_analyzer.neightborhood.pattern_utils import (
    get_regex_first_k, get_regex_last_k, open_regex,
    get_n_neighborhood, get_zero_neighborhood)
from src.eregex.parser import ERegexParser
from src.dynamic_analyzer.fuzzer.abstract_fuzzer import Fuzzer
from src.multipattern.repattern import REPattern, REVariable
from src.multipattern.remultipattern import REMultipattern
from src.eregex.regex import Regex, ConcatenationRegex


class REPatternFuzzer(Fuzzer):
    """Main structured fuzzing algorithm implementation for re-patterns"""

    def _simplify_pattern(self, pattern: REPattern) -> REPattern:
        for elem in pattern.value:
            if isinstance(elem, REVariable) and isinstance(elem.regex, ConcatenationRegex):
                sub = [REVariable(v) if type(v, Regex) else v for v in elem.regex.value]
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
        if self.static_analyzer(pattern.sub(start, end + 1).get_regular_str()) == NO_AMBIGUOUS:
            return
        intersections = set()
        for k in radius_range:
            x_1 = self._get_neighborhood(start, pattern, k)
            x_2 = self._get_neighborhood(end, pattern, k)
            if len(x_1) == 0 or len(x_2) == 0:
                break
            cap = x_1.intersection(x_2)
            if len(cap) == 0:
                return
            if end - start > 1:
                for n in range(1, k // 2):
                    trans = self._get_neighborhood(start + 1, pattern, k, n)
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
            attack_format: str,
            inter: str,
            subs: List[str],
            trans_subs: List[str],
            n: int = 2) -> str:
            # corners
            for i, word in enumerate(subs):
                attack_format = attack_format.replace(f"{{{i}}}", word * n)
            # transition
            for i, word in enumerate(trans_subs):
                attack_format = attack_format.replace(f"[{i}]", word)
            # core
            first_sub = subs[0]
            inter_start = first_sub.find(inter)
            core = first_sub[:inter_start] + inter * (2 * n)
            attack = attack_format.replace("{2}", core)
            return attack
        
        def format_regex(
            attack_format: str,
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
  
        target_vars = [pattern.value[start], pattern.value[end]]
        trans_vars = [v for v in pattern.value[start + 1:end] if isinstance(v, REVariable)]
        attack_format = ""
        cast_trans = False

        # may be faster if pattern.value[:start] + {2} + not_last,
        # but for pattern learning it's better
        for i, elem in enumerate(pattern.value):
            if i == start:
                attack_format += "{2}"
            elif start < i <= end:
                continue
            elif isinstance(elem, str):
                attack_format += elem
            elif elem in trans_vars:
                if not cast_trans and i < start:
                    cast_trans = True
                attack_format += f"[{trans_vars.index(elem)}]"
            elif elem in target_vars:
                attack_format += f"{{{target_vars.index(elem)}}}"
            else:
                attack_format += next(open_regex(elem.regex))
        attack_format += get_attack_postfix(pattern.get_regex())

        ext_regex = pattern.get_ext_regex()
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
                regex = pattern.sub(start + 1, end).get_ext_regex()
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
                        word = format_word(attack_format, inter, target_sub, trans_sub, n=2)
                        time = self.matcher.match_word(word, ext_regex, timeout)
                        score = time / len(word)
                        if score > max_score:
                            max_score = score
                            result = [inter, target_sub, trans_sub]
                    if not cast_trans:
                        target_sub = [start_sub, end_sub]
                        trans_sub = []
                        word = format_word(attack_format, inter, target_sub, trans_sub, n=2)
                        time = self.matcher.match_word(word, ext_regex, timeout)
                        score = time / len(word)
                        if score > max_score:
                            max_score = score
                            result = [inter, target_sub, trans_sub]

        if result is None:
            return
        times, lens = [], []
        for k in range(1, max_iter):
            word = format_word(attack_format, *result, n=k)
            lens.append(len(word))
            time = self.matcher.match_word(word, ext_regex, timeout)
            if time == timeout:
                return EXP_AMBIGUOUS, format_regex(attack_format, *result)
            times.append(time)
        amb = self.ambiguity_analyzer.analyze(times, lens)
        if amb > NO_AMBIGUOUS:
            return amb, format_regex(attack_format, *result)
        
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
    
    def run(
        self,
        pattern: REPattern,
        max_radius: int = 10,
        timeout: float = 0.5,
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
        pattern = self._simplify_pattern(pattern)
        prevs = []
        pumping_groups = {}
        if self.static_analyzer(pattern.get_regular_str()) == NO_AMBIGUOUS:
            return pumping_groups
        for i, elem in enumerate(pattern.value):
            if isinstance(elem, REVariable):
                status = self.static_analyzer(str(elem.regex))
                if status > NO_AMBIGUOUS:
                    attack_pattern = make_attack_pattern(
                        pattern.sub(i).get_ext_regex(),
                        elem.regex,
                        get_attack_postfix(pattern.get_regex())
                    )
                    self._update_pumping_groups(
                        pumping_groups,
                        (status, attack_pattern))
                    if first:
                        return pumping_groups
                if self.static_analyzer(pattern.sub(i + 1).get_regular_str()) == NO_AMBIGUOUS:
                    continue
                if len(prevs) != 0:
                    for prev in prevs:
                        if check_intersection(
                            prevs[prev + 1:],
                            [pattern.value[i], pattern.value[prev]]):
                            continue
                        trans_len = pattern.slice_len(prev + 1, i)
                        radius_range = range(trans_len, trans_len + max_radius)
                        intersections = self._pump_neighborhood(pattern, prev, i, radius_range)
                        if intersections is None:
                            continue
                        attack = self.pump(pattern, prev, i, intersections, timeout)
                        if attack is not None:
                            self._update_pumping_groups(pumping_groups, attack)
                            if first:
                                return pumping_groups
                prevs.append(i)
        return pumping_groups

from typing import List, Set, Dict, Tuple, Optional, Iterable

from src.const import (EXP_AMBIGUOUS, NO_AMBIGUOUS)
from src.dynamic_analyzer.utils import (
    trim_last, trim_first, replace_with_var,
    make_attack_pattern, get_attack_postfix,
    check_intersection, get_prefix_overlap)
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
    
    def _get_pump_prefix(
        self, 
        w1: str, 
        w2: str, 
        iter_limit: int = 10) -> Optional[Tuple[str, str]]:
        overlap = get_prefix_overlap(w1, w2)
        w1_copy = w1
        w2_copy = w2
        count = len(overlap)
        if count == 0:
            return
        for i in range(2, iter_limit):
            w1_copy = overlap + w1_copy
            w2_copy += w2
            if len(get_prefix_overlap(w1, w2)) != count * i:
                return
        return overlap, w1[len(overlap):]
    
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
                result = self._get_pump_prefix(word[::-1], inter, iter_limit)
                if result is not None:
                    return result[1][::-1], result[0][::-1]
        else:
            for word in open_regex(var.regex, rec_limit):
                var.regex.delete_substitution()
                result = self._get_pump_prefix(word, inter[::-1], iter_limit)
                if result is not None:
                    return result
    
    def pump(
        self,
        pattern: REPattern,
        start: int,
        end: int,
        intersection: List[str],
        timeout: float = 0.5,
        num_epochs: int = 10,
        rec_limit: int = 3,
        iter_range: List[int] = [1, 100, 10],
        genetic: bool = False,
        iter_limit: int = 10) -> Optional[Tuple[int, REPattern]]:
        """Synchronous pumping

        Args:
            pattern (REPattern).
            start (int): index of the first variable.
            end (int): index of the last variable.
            intersection (List[str]): list of neighborhoods.
            timeout (float, optional): matching timeout. Defaults to 0.5.
            num_epochs (int, optional): number of epochs to evolve. Defaults to 10.
            rec_limit (int, optional): limit for opening transition. Defaults to 3.
            iter_range (List[int], optional): range of pumping iterations. Defaults to [1, 100, 10].

        Returns:
            Optional[Tuple[int, REPattern]]: (ambiguity status, multipattern).
        """
        def format_word(
            inter: str,
            target_subs: List[Tuple[str, str]],
            trans_subs: List[str],
            n: int = 2) -> str:
            for var, sub in trans_subs.items():
                var.regex.substitute(sub)
            
            first_sub = target_subs[0]
            target_vars[0].regex.substitute(first_sub[0] + first_sub[1] * n)

            last_sub = target_subs[1]
            target_vars[1].regex.substitute(last_sub[0] * n + last_sub[1])

            core = first_sub[0] + inter * (2 * n)
            attack = next(open_regex(pattern_regex.sub(end=start))) + core + postfix
            pattern_regex.delete_substitution()
            return attack
        
        def format_regex(
            inter: str,
            target_subs: List[Tuple[str, str]],
            trans_subs: List[str]) -> REPattern:
            for var, sub in trans_subs.items():
                var.regex.substitute(sub)
            
            target_regex = []
            # first var
            first_sub = target_subs[0]
            target_vars[0].regex.substitute("{0}")
            target_regex.append(REVariable(ERegexParser(first_sub[0] + f"({first_sub[1]})*").parse()))

            # last var
            last_sub = target_subs[1]
            target_vars[1].regex.substitute("{1}")
            target_regex.append(REVariable(ERegexParser(f"({last_sub[0]})*" + last_sub[1]).parse()))

            # core
            target_regex.append(REVariable(ERegexParser(first_sub[0] + f"({inter})*").parse()))
            attack_format = next(open_regex(pattern_regex.sub(end=start))) + "{2}" + \
                next(open_regex(pattern_regex.sub(start=end + 1))) + postfix
            pattern_regex.delete_substitution()
            return replace_with_var(attack_format, target_regex)
  
        target_vars = [pattern.value[start], pattern.value[end]]
        trans_vars = [v for v in pattern.value[start + 1:end] if isinstance(v, REVariable)]
        pattern_regex = ERegexParser(pattern.get_ext_regex()).parse()

        postfix = get_attack_postfix(pattern_regex)
        cast_trans = False
        result = None
        for inter in intersection:
            # target vars
            target_subs = {}
            for i, var in enumerate(target_vars):
                if genetic:
                    regex = var.regex
                    if i == 0:
                        fitness_func = lambda x: self.matcher.match_word(x, str(regex)) \
                            and self._get_pump_prefix(x[::-1], inter, iter_limit) is not None
                    else:
                        fitness_func = lambda x: self.matcher.match_word(x, str(regex)) \
                            and self._get_pump_prefix(x, inter[::-1], iter_limit) is not None
                    genetic_result = self.fuzzer.cast(
                        [inter],
                        [""] + trim_last(get_regex_first_k(regex, k=len(regex))) + \
                        trim_first(get_regex_last_k(regex, k=len(regex))),
                        fitness_func, num_epochs)
                    if genetic_result is None:
                        break
                    prefix = get_prefix_overlap(genetic_result, inter)
                    if i == 0:
                        target_subs[var] = (genetic_result[::-1][:len(prefix)], prefix[::-1])
                    else:
                        target_subs[var] = (prefix, genetic_result[len(prefix):])
                else:
                    target_subs[var] = self._neighborhood_search(var, inter, i, iter_limit, rec_limit)
            if len(target_subs) < 2:
                continue
            
            # transition vars
            trans_subs = {}
            if cast_trans:
                double_inter = inter * 2
                traget_words = [
                    "".join(target_subs[target_vars[0]])[::-1],
                    "".join(target_subs[target_vars[1]])]
                regex = pattern_regex.sub(start + 1, end)
                for word in open_regex(regex, rec_limit=len(inter)):
                    if double_inter.find(word) > -1 and \
                        get_prefix_overlap(traget_words[0], word) and \
                            get_prefix_overlap(traget_words[1], word[::-1]):
                        for var in trans_vars:
                            trans_subs[var] = var.regex.substitution
                    regex.delete_substitution()
                if len(trans_subs) == 0:
                    continue
            result = [inter, target_subs, trans_subs]

        if result is None:
            return
        ext_regex = pattern.get_ext_regex()
        times, lens = [], []
        for k in range(*iter_range):
            word = format_word(*result, n=k)
            time = self.matcher.match_word(word, ext_regex, timeout)
            if time == timeout:
                return EXP_AMBIGUOUS, format_regex(*result)
            lens.append(len(word))
            times.append(time)
        amb = self.ambiguity_analyzer.analyze(times, lens)
        if amb > NO_AMBIGUOUS:
            return amb, format_regex(*result)
        
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

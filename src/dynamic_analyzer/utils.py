from typing import Set, Callable, Iterator, List, Any, Optional, Dict, Tuple
import re
import random
import numpy as np

from src.const import ALPHABET, EPSILON
from src.dynamic_analyzer.neightborhood.pattern_utils import open_regex
from src.multipattern.recpattern import RECPattern
from src.dynamic_analyzer.const import BASE_ID, PUMP_ID
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, BackrefRegex,
    AlternativeRegex, ConcatenationRegex)


def get_last(regex: Regex) -> Set[str]:
    if isinstance(regex, BaseRegex):
        return set(str(regex))
    if isinstance(regex, AlternativeRegex):
        last_set = set()
        for value in regex.value:
            last_set.update(get_last(value))
        return last_set
    if isinstance(regex, ConcatenationRegex):
        last_set = set()
        for value in regex.value[::-1]:
            curr_last = get_last(value)
            last_set.update(curr_last)
            if EPSILON not in curr_last:
                return last_set
        return last_set
    if isinstance(regex, StarRegex):
        last_set = get_last(regex.value)
        last_set.add(EPSILON)
        return last_set
    return get_last(regex.regex_value)


def key_generator() -> Iterator[str]:
    i = 0
    while True:
        yield str(i)
        i += 1


def get_divisors(number: int) -> Set[int]:
    result = {1, number}
    for divisor in range(2, number // 2  + 1):
        if number % divisor == 0:
            result.add(divisor)
    return result


def get_generator(generate_func: Callable, *args) -> Iterator[Any]:
    while True:
        yield generate_func(*args)


def get_digit_prefix(word: str) -> int:
    result = ""
    for char in word:
        if re.match(r"[0-9]", char):
            result += char
        else:
            break
    return int(result)


def check_intersection(
    source: List[Any],
    target: List[Any]) -> bool:
    for s in source:
        if s in target:
            return True
    return False

# TODO: modify
def check_regex_intersection(
    source: List[Regex],
    target: List[Regex]) -> bool:
    for s in source:
        if s in target:
            return True
    return False


def get_attack_postfix(regex: Regex) -> str:
    return random.choice(list(ALPHABET.difference(get_last(regex))))


def trim_last(words: Tuple[Set[str], Set[str]]) -> List[str]:
    words = words[0].union(words[1])
    return list(set([w[:i] for w in words for i in range(1, len(w) + 1)]))


def trim_first(words: Tuple[Set[str], Set[str]]) -> List[str]:
    words = words[0].union(words[1])
    return list(set([w[i:] for w in words for i in range(len(w))]))


# def make_attack_pattern(
#     prefix: Regex,
#     var: Regex,
#     suffix: Optional[str] = None) -> REPattern:
#     attack = [next(open_regex(prefix)), REVariable(var)]
#     if suffix is not None:
#         attack.append(suffix)
#     return REPattern(attack)


# def make_attack_pattern(
#     main_regex: Regex,
#     regex: Regex,
#     suffix: Optional[str] = None) -> RECPattern:
#     regex.substitute(str(regex))
#     result = next(open_regex(main_regex))
#     if suffix is not None:
#         attack.append(suffix)
#     return RECPattern(attack)


def invert_mask(indexes: List[int], size: int) -> np.ndarray:
    mask = np.ones(size, dtype=bool)
    mask[indexes] = False
    return mask


def get_overlapping(s1: str, s2: str) -> str:
    result = ""
    len1, len2 = len(s1), len(s2)
    for i in range(len1):
        match = ""
        for j in range(len2):
            if (i + j < len1 and s1[i + j] == s2[j]):
                match += s2[j]
                if i + j == len1 - 1 and len(match) > len(result): result = match
            else:
                break
    return result


# def replace_with_var(word: str, vars: List[REVariable]|Dict[int, REVariable]) -> REPattern:
#     i = 0
#     pattern = []
#     while i < len(word):
#         if word[i] != "{":
#             pattern.append(word[i])
#         else:
#             id = get_digit_prefix(word[i+1:])
#             pattern.append(vars[id])
#             i += len(id) + 1
#         i += 1
#     return REPattern(pattern)


# def format_static(main_regex: Regex, regex: Regex, regex_string: str) -> REPattern:
#     regex.substitute("{0}")
#     result = next(open_regex(main_regex))
#     result += get_attack_postfix(main_regex)
#     main_regex.delete_substitution()
#     return replace_with_var(result, [REVariable(ERegexParser(regex_string).parse())])


def format_static(
    main_regex: Regex,
    regex: Regex,
    regex_string: str,
    idx: str = "0") -> RECPattern:
    s_name = "[" + BASE_ID + idx + "]" 
    regex.substitute(s_name)
    vars = {s_name: regex_string}
    return format_recpattern(main_regex, vars)


def get_backrefs(source: Regex) -> List[BackrefRegex]:
    if isinstance(source, BaseRegex):
        return []
    if isinstance(source, BackrefRegex):
        return [source]
    elif isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
        nodes = []
        for value in source.value:
            nodes += get_backrefs(value)
        return nodes
    return get_backrefs(source.value)


def format_recpattern(
    main_regex: Regex,
    vars: Optional[Dict] = None) -> RECPattern:
    vars = {} if vars is None else vars
    for p in get_backrefs(main_regex):
        name = "[" + p.value.replace("\\", BASE_ID) + "]"
        p.substitute(name)
        p.regex_value.substitute(name)
        if name not in vars:
            vars[name] = format_recpattern(p.regex_value)
    result = next(open_regex(main_regex)) + get_attack_postfix(main_regex)
    main_regex.delete_substitution()
    return RECPattern(result, vars)


def format_nssnf(main_regex: Regex, regex: Regex, idx: str) -> RECPattern:
    s_name = "[" + PUMP_ID + idx + "]" 
    regex.substitute(s_name)
    vars = {s_name: format_recpattern(regex)}
    return format_recpattern(main_regex, vars)


def format_recattack(
    main_regex: Regex,
    regex: Regex,
    pattern: RECPattern,
    idx: str) -> RECPattern:
    s_name = "[" + PUMP_ID + idx + "]" 
    regex.substitute(s_name)
    vars = pattern.get_all_vars()
    vars[s_name] = pattern
    return format_recpattern(main_regex, vars)

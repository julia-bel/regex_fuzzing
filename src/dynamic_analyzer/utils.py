from typing import Set, Callable, Iterator, List, Any, Optional, Dict, Tuple
import re
import random
import numpy as np
import matplotlib.pyplot as plt

from src.const import ALPHABET, EPSILON
from src.dynamic_analyzer.neightborhood.pattern_utils import open_regex
from src.multipattern.recpattern import RECPattern
from src.dynamic_analyzer.const import BASE_ID, PUMP_ID
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, BackrefRegex,
    AlternativeRegex, ConcatenationRegex, get_substitutions)


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


def get_attack_postfix(regex: Regex) -> str:
    return random.choice(list(ALPHABET.difference(get_last(regex))))


def trim_last(words: Tuple[Set[str], Set[str]]) -> List[str]:
    words = words[0].union(words[1])
    return list(set([w[:i] for w in words for i in range(1, len(w) + 1)]))


def trim_first(words: Tuple[Set[str], Set[str]]) -> List[str]:
    words = words[0].union(words[1])
    return list(set([w[i:] for w in words for i in range(len(w))]))


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


def check_regex_intersection(
    source: List[Regex],
    target: List[Regex]) -> bool:
    for s in source:
        if s in target:
            return True
    return False


def format_static(
    main_regex: Regex,
    regex: Regex,
    regex_string: str,
    idx: Iterator[str]) -> RECPattern:
    regex_name = "[" + BASE_ID + next(idx) + "]" 
    regex.substitute(regex_name)
    vars = {regex_name: regex_string}
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
    vars: Optional[Dict] = None,
    postfix: bool = True) -> RECPattern:
    vars = {} if vars is None else vars
    for p in get_backrefs(main_regex):
        name = "[" + p.value.replace("\\", BASE_ID) + "]"
        if name not in vars:
            vars[name] = format_recpattern(p.regex_value, postfix=False)
        p.substitute(name)
        p.regex_value.substitute(name)
    result = next(open_regex(main_regex))
    if postfix:
        result += get_attack_postfix(main_regex)
    history = get_substitutions(main_regex)
    main_regex.delete_substitution()
    return RECPattern(result, vars, history)


def format_nssnf(main_regex: Regex, regex: Regex, value: Regex, idx: Iterator[str]) -> RECPattern:
    regex_name = "[" + PUMP_ID + next(idx) + "]"
    regex.substitute(regex_name)

    inner = value.value
    inner_name = "[" + PUMP_ID + next(idx) + "]"
    inner_pattern = format_recpattern(inner)
    inner.substitute(inner_name)

    vars = {regex_name: RECPattern(f"(({inner_name})*)*", {inner_name: inner_pattern})}
    return format_recpattern(main_regex, vars)


def format_recattack(
    main_regex: Regex,
    regex: Regex,
    pattern: RECPattern,
    idx: Iterator[str]) -> RECPattern:
    for r, sub in pattern.history.items():
        r.substitute(sub)
    regex_name = "[" + PUMP_ID + next(idx) + "]" 
    regex.substitute(regex_name)
    vars = pattern.get_all_vars()
    vars[regex_name] = pattern
    return format_recpattern(main_regex, vars)


def plot_dependance(
    time: List[float],
    length: List[int],
    title: str,
    linestyle: str = '-o',
    dpi: int = 300,
    keys: Iterator[str] = key_generator()):

    plt.figure(dpi=dpi)
    plt.plot(length, time, linestyle)
    plt.xlabel('Length, chars')
    plt.ylabel('Time, seconds')
    plt.title(title)
    plt.savefig(f"src/visualization/dependance_{next(keys)}.png", dpi=dpi)

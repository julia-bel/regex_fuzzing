from typing import Set, Callable, Iterator, List, Any, Optional
import re
import random
import numpy as np

from src.const import ALPHABET
from src.dynamic_analyzer.neightborhood.pattern_utils import open_regex
from src.multipattern.repattern import REPattern, REVariable
from src.const import EPSILON
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex,
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


def get_divisors(number: int) -> Set[int]:
    result = {1, number}
    for divisor in range(2, number // 2  + 1):
        if number % divisor == 0:
            result.add(divisor)
    return result


def get_generator(generate_func: Callable, *args) -> Iterator[Any]:
    while True:
        yield generate_func(*args)


def get_digit_prefix(word: str):
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


def trim_last(words: List[str]) -> List[str]:
    return list(set([w[:i] for w in words for i in range(1, len(w) + 1)]))


def trim_first(words: List[str]) -> List[str]:
    return list(set([w[i:] for w in words for i in range(len(w))]))


def make_attack_pattern(
    prefix: Regex,
    var: Regex,
    suffix: Optional[str] = None) -> REPattern:
    attack = [next(open_regex(prefix)), REVariable(var)]
    if suffix is not None:
        attack.append(suffix)
    return REPattern(attack)


def invert_mask(indexes: List[int], size: int) -> np.ndarray:
    mask = np.ones(size, dtype=bool)
    mask[indexes] = False
    return mask

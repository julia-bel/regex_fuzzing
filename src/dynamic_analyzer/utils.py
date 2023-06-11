from typing import Set, Callable, Iterator, Tuple, List, Any
from itertools import product
import re

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


def get_generator(generate_func: Callable, *args) -> Iterator:
    return generate_func(*args)


def get_digit_prefix(word: str):
    result = ""
    for char in word:
        if re.match(r"[0-9]", char):
            result += char
        else:
            break
    return int(result)


def get_regex_first_k(regex: Regex, k: int) -> Tuple[Set[str], Set[str]]:
    exact = set()
    sub = set() #  if k > 0 else set("")
    if isinstance(regex, BaseRegex):
        if k == 1:
            exact.add(str(regex))
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            e, s = get_regex_first_k(value, k)
            exact.update(e)
            sub.update(s)
    elif isinstance(regex, ConcatenationRegex):
        e, s = get_regex_first_k(regex.value[0], k)
        if len(regex.value) == 1:
            exact.update(e)
            sub.update(s)
        else:
            sub.update(e, s)
            for part in range(k + 1):
                prefix, _ = get_regex_first_k(regex.value[0], part)
                suffix_e, suffix_s = get_regex_first_k(regex.sub(1), k - part)
                exact.update(set(p + s for p in prefix for s in suffix_e))
                sub.update(set(p + s for p in prefix for s in suffix_s))
    elif isinstance(regex, StarRegex):
        if k == 0:
            exact.add("")
        e, s = get_regex_first_k(regex.value, k)
        exact.update(e)
        sub.update(s)
        for part in range(k):
            e, s = get_regex_first_k(regex.value, part)
            if part != 0 and len(e) > 0:
                for i in range(1, k // part):
                    mod = k - i * part
                    if mod == 0:
                        exact.update(set(item * i for item in e))
                    else:
                        ex, s = get_regex_first_k(regex.value, mod)
                        exact.update(set(prefix * i + suffix for prefix in e for suffix in ex.union(s)))
    else: # TODO: generator, that saves init state of backref
        return get_regex_first_k(regex.regex_value, k)
    return exact, sub

   
def get_regex_last_k(regex: Regex, k: int) -> Tuple[Set[str], Set[str]]:
    exact, sub = get_regex_first_k(regex.reverse(), k)
    exact = set(e[::-1] for e in exact)
    sub = set(s[::-1] for s in sub)
    return exact, sub


def check_intersection(
    source: List[Any],
    target: List[Any]) -> bool:
    for s in source:
        if s in target:
            return True
    return False


def open_regex(regex: Regex, rec_limit: int = 1) -> Iterator[str]:
    if isinstance(regex, BaseRegex):
        yield str(regex)
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            for child in open_regex(value, rec_limit):
                regex.substitute(child)
                yield child
        regex.substitute(None)
    elif isinstance(regex, ConcatenationRegex):
        for first_child in open_regex(regex.value[0], rec_limit):
            for last_child in open_regex(ConcatenationRegex(regex.value[1:]), rec_limit):
                regex.substitute(first_child + last_child)
                yield first_child + last_child
        regex.substitute(None)
    elif isinstance(regex, StarRegex):
        values = list(set(v for v in open_regex(regex.value, rec_limit)))
        for limit in range(rec_limit):
            for permutation in product(values, limit):
                yield permutation
    else:
        yield regex.regex_value.substitution


def trim_last(words: List[str]) -> List[str]:
    return list(set([w[:i] for w in words for i in range(1, len(w) + 1)]))


def trim_first(words: List[str]) -> List[str]:
    return list(set([w[i:] for w in words for i in range(len(w))]))

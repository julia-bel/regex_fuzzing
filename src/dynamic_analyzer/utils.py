from typing import Set

from src.const import EPSILON
from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, AlternativeRegex, ConcatenationRegex)


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
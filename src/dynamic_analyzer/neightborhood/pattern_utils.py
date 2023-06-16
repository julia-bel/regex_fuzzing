from typing import Set, Iterator, Tuple
from itertools import product

from src.eregex.regex import (
    Regex, BaseRegex, StarRegex,
    AlternativeRegex, ConcatenationRegex)


def open_regex(regex: Regex, rec_limit: int = 1) -> Iterator[str]:
    if regex.substitution is not None:
        yield regex.substitution
    elif isinstance(regex, BaseRegex):
        regex.substitute(str(regex))
        yield str(regex)
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            for child in open_regex(value, rec_limit):
                regex.substitute(child)
                yield child
        regex.substitute(None)
    elif isinstance(regex, ConcatenationRegex):
        if len(regex.value) == 0:
            regex.substitute("")
            yield ""
        if len(regex.value) == 1:
            print(f"single child: {regex.value[0]}")
            print("")
            for first_child in open_regex(regex.value[0], rec_limit):
                regex.substitute(first_child)
                yield first_child
        else:
            for first_child in open_regex(regex.value[0], rec_limit):
                for last_child in open_regex(ConcatenationRegex(regex.value[1:]), rec_limit):
                    regex.substitute(first_child + last_child)
                    yield first_child + last_child
        regex.substitute(None)
    elif isinstance(regex, StarRegex):
        values = list(set(v for v in open_regex(regex.value, rec_limit)))
        for limit in range(rec_limit):
            for permutation in product(values, repeat=limit):
                permutation = "".join(permutation)
                regex.substitute(permutation)
                yield permutation
    else:
        if regex.regex_value.substitution is not None:
            regex.substitute(regex.regex_value.substitution)
            yield regex.regex_value.substitution
        else:
            for parent_sub in open_regex(regex.regex_value, rec_limit):
                regex.substitute(parent_sub)
                yield parent_sub


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
        for part in range(1, k):
            # print(f"k={part}")
            e, s = get_regex_first_k(regex.value, part)
            # print(f"first: {e, s}")
            if part != 0 and len(e) > 0:
                for i in range(1, k // part + 1):
                    # print("here")
                    mod = k - i * part
                    if mod == 0:
                        exact.update(set("".join(item) for item in product(e, repeat=i)))
                    else:
                        ex, s = get_regex_first_k(regex.value, mod)
                        exact.update(set("".join(prefix) + suffix
                            for prefix in product(e, repeat=i) for suffix in ex.union(s)))
    else:
        return get_regex_first_k(regex.regex_value, k)
    return exact, sub

   
def get_regex_last_k(regex: Regex, k: int) -> Tuple[Set[str], Set[str]]:
    exact, sub = get_regex_first_k(regex.reverse(), k)
    exact = set(e[::-1] for e in exact)
    sub = set(s[::-1] for s in sub)
    return exact, sub


def get_n_neighborhood(start_regex: Regex, end_regex: Regex, n: int, k: int) -> Set[str]:
    prefix = get_regex_last_k(start_regex, n)
    # print(f"prefixes: {prefix}")
    suffix = get_regex_first_k(end_regex, k - n)
    # print(f"suffixes: {suffix}")
    prefix = prefix[0].union(prefix[1])
    suffix = suffix[0].union(suffix[1])
    neighborhood = set(p + s for p in prefix for s in suffix)
    return neighborhood


def get_zero_neighborhood(regex: Regex, k: int) -> Set[str]:
    print(f"regex: {regex} k: {k}")
    neighborhood = set()
    if isinstance(regex, BaseRegex):
        if len(regex) == k:
            neighborhood.update(regex.value)
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            neighborhood.update(get_zero_neighborhood(value, k))
    elif isinstance(regex, ConcatenationRegex):
        for i, value in enumerate(regex.value[:-1]):
            for n in range(1, k + 1):
                neighborhood.update(get_n_neighborhood(value, regex.sub(start=i + 1), n, k))
        neighborhood.update(get_zero_neighborhood(regex.value[-1], k))
    else: # if isinstance(regex, StarRegex):
        for n in range(k + 1):
            # print(f"n: {n}")
            neighborhood.update(get_n_neighborhood(regex, regex, n, k))
    # print(f"neighborhood: {neighborhood}")
    return neighborhood

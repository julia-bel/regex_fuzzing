from __future__ import annotations
from typing import Iterator, Tuple, Dict, Optional, List
from itertools import product
from copy import deepcopy

from src.eregex.regex import (
    Regex, BaseRegex, StarRegex,
    AlternativeRegex, ConcatenationRegex)


class Path:
    """Container of {Regex: substitution, ...}"""
    def __init__(self, value: Dict[Regex, str]) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Path) and other.value == self.value
    
    def add(self, regex: Regex, sub: str):
        self.value[regex] = sub

    def merge(self, other: Path) -> Optional[Path]:
        new_value = deepcopy(other.value)
        for regex, sub in self.value:
            if regex in new_value:
                if sub != new_value[regex]:
                    return
            else:
                new_value[regex] = sub
        return Path(new_value)


def update_storage(
    storage: Dict[str, List[Path]],
    other: Dict[str, List[Path]]):
    for prefix, paths in other.items():
        if prefix in storage:
            storage_paths = storage[prefix]
        else:
            storage_paths = []
        for path in paths:
            if path not in storage_paths:
                storage_paths.append(path)


def intersect_storages(
    s1: Dict[str, List[Path]],
    s2: Dict[str, List[Path]]) -> Dict[str, List[Path]]:
    storage = {}
    for prefix, paths in s1.items():
        if prefix in s2:
            storage[prefix] = []
            storage_paths = storage[prefix]
            for p1 in paths:
                for p2 in s2[prefix]:
                    new_path = p1.merge(p2)
                    if new_path is not None and new_path not in storage_paths:
                        storage_paths.append(new_path)
    return storage


def concat_storeges(
    prefix_set: Dict[str, List[Path]],
    suffix_set: Dict[str, List[Path]]) -> Dict[str, List[Path]]:
    storage = {}
    for prefix, p_paths in prefix_set:
        for suffix, s_paths in suffix_set:
            word = prefix + suffix
            paths = []
            for p in p_paths:
                for s in s_paths:
                    path = p.merge(s)
                    if path is not None:
                        paths.append(path)
            if word in storage:
                storage_paths = storage[word]
            else:
                storage_paths = []
            for path in paths:
                if path not in storage_paths:
                    storage_paths.append(path)
    return storage


def add_to_storage(
    storage: Dict[str, List[Path]],
    word: str,
    paths: List[Path]):
    if word in storage:
        storage_paths = storage[word]
    else:
        storage_paths = []
    for path in paths:
        if path not in storage_paths:
            storage_paths.append(path)


def get_regex_first_k(regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
    exact = {} # exac = {"first_k_prefix": [Path(), Path(), ...]}
    sub = {} #  if k > 0 else set("")
    if isinstance(regex, BaseRegex):
        if k <= len(regex):
            result = str(regex)
            add_to_storage(exact, result[:k], [Path({regex: {result}})])
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            e, s = get_regex_first_k(value, k)
            update_storage(exact, e)
            update_storage(sub, s)
    elif isinstance(regex, ConcatenationRegex):
        e, s = get_regex_first_k(regex.value[0], k)
        if len(regex.value) == 1:
            update_storage(exact, e)
            update_storage(sub, s)
        else:
            update_storage(sub, e)
            update_storage(sub, s)
            for part in range(k + 1):
                prefix, _ = get_regex_first_k(regex.value[0], part)
                suffix_e, suffix_s = get_regex_first_k(regex.sub(1), k - part)
                update_storage(exact, concat_storeges(prefix, suffix_e))
                update_storage(sub, concat_storeges(prefix, suffix_s))
    elif isinstance(regex, StarRegex):
        if k == 0:
            add_to_storage(exact, "", [Path({regex: ""})])
        e, s = get_regex_first_k(regex.value, k)
        update_storage(exact, e)
        update_storage(sub, s)
        for part in range(k):
            e, s = get_regex_first_k(regex.value, part)
            if part != 0 and len(e) > 0:
                for i in range(1, k // part):
                    mod = k - i * part
                    if mod == 0:
                        # add_to_storage(exact, "", [Path({regex: ""})]) # add Star value
                        update_storage(exact, {k * i: v for k, v in e.items})
                    else:
                        ex, s = get_regex_first_k(regex.value, mod)
                        iter_prefix = {k * i: v for k, v in e.items}
                        update_storage(ex, s)
                        update_storage(exact, concat_storeges(iter_prefix, ex))
    else:
        return get_regex_first_k(regex.regex_value, k)
    return exact, sub


def open_regex(regex: Regex, rec_limit: int = 1) -> Iterator[str]:
    if regex.substitution is not None:
        yield regex.substitution
    elif isinstance(regex, BaseRegex):
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
        if regex.regex_value.substitution is not None:
            yield regex.regex_value.substitution
        else:
            for parent_sub in open_regex(regex.regex_value, rec_limit):
                yield parent_sub


def reopen_regex(regex: Regex, memory: Dict[Regex, str], rec_limit: int = 1) -> Iterator[str]:
    if regex in memory:
        regex.substitute(memory[regex])
        yield memory[regex]
    elif isinstance(regex, BaseRegex):
        regex_str = str(regex)
        regex.substitute(regex_str)
        yield regex_str
    elif isinstance(regex, AlternativeRegex):
        is_fixed = False
        for value in regex.value:
            if value in memory:
                is_fixed = True
                yield memory[regex]
        if not is_fixed:
            for value in regex.value:
                for child in reopen_regex(value, memory, rec_limit):
                    regex.substitute(child)
                    yield child
    elif isinstance(regex, ConcatenationRegex):
        for first_child in reopen_regex(regex.value[0], memory, rec_limit):
            for last_child in reopen_regex(ConcatenationRegex(regex.value[1:]), memory, rec_limit):
                regex.substitute(first_child + last_child)
                yield first_child + last_child
    elif isinstance(regex, StarRegex):
        values = list(set(v for v in reopen_regex(regex.value, rec_limit)))
        for limit in range(rec_limit):
            for permutation in product(values, limit):
                yield permutation
    else:
        if regex.regex_value.substitution is not None:
            regex.substitute(regex.regex_value.substitution)
            yield regex.regex_value.substitution
        else:
            for parent_sub in reopen_regex(regex.regex_value, memory, rec_limit):
                regex.substitute(regex.regex_value.substitution)
                yield parent_sub
    regex.substitute(None)

   
def get_regex_last_k(regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
    exact, sub = get_regex_first_k(regex.reverse(), k)
    exact = {e[::-1]: v for e, v in exact.items()}
    sub = {s[::-1]: v for s, v in sub.items()}
    return exact, sub


def get_n_neighborhood(start_regex: Regex, end_regex: Regex, n: int, k: int) -> Dict[str: List[Path]]:
    prefix, s_prefix = get_regex_last_k(start_regex, n)
    suffix, s_saffix = get_regex_first_k(end_regex, k - n)
    # prefix = prefix[0].union(prefix[1])
    # suffix = suffix[0].union(suffix[1])
    update_storage(prefix, s_prefix)
    update_storage(suffix, s_saffix)

    # neighborhood = set(p + s for p in prefix for s in suffix)
    neighborhood = concat_storeges(prefix, suffix)
    return neighborhood


def get_zero_neighborhood(regex: Regex, k: int) -> Dict[str: List[Path]]:
    neighborhood = {}
    if isinstance(regex, BaseRegex):
        value = regex.value
        for i in range(len(regex) - k + 1):
            # neighborhood.update(value[i:])
            add_to_storage(neighborhood, value[i:i + k], [Path({regex: {value}})])
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            # neighborhood.update(get_zero_neighborhood(value, k))
            update_storage(neighborhood, get_zero_neighborhood(value, k))
    elif isinstance(regex, ConcatenationRegex):
        for i in range(len(regex.value)):
            e, s = get_regex_first_k(regex.sub(start=i), k)
            # neighborhood.update(e, s)
            update_storage(neighborhood, e)
            update_storage(neighborhood, s)
    else: # if isinstance(regex, StarRegex):
        for n in range(k + 1):
            # neighborhood.update(get_n_neighborhood(regex, regex, n, k))
            update_storage(neighborhood, get_n_neighborhood(regex, regex, n, k))
    return neighborhood

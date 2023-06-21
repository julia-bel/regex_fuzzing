from __future__ import annotations
from typing import Iterator, Tuple, Dict, Optional, List, Any, Set, Callable
from itertools import product
from json import dumps

from src.eregex.regex import (
    Regex, BaseRegex, StarRegex, AlternativeRegex, ConcatenationRegex,
    BackrefRegex, copy_regex)


class Path:
    """Container of {Regex: substitution, ...}"""
    def __init__(self, value: Dict[Regex, Any]) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Path) and other.value == self.value
    
    def __hash__(self) -> int:

        def to_json(value: Any):
            if isinstance(value, str):
                return value
            if isinstance(value, List):
                return [to_json(v) for v in value]
            return hash(value)
        
        json_dict = {to_json(r): to_json(v) for r, v in self.value.items()}
        return hash(dumps(json_dict, sort_keys=True))
    
    def add(self, regex: Regex, sub: Any):
        self.value[regex] = sub

    def merge(self, other: Path) -> Optional[Path]:
        new_value = {k: v for k, v in other.value.items()}
        for regex, sub in self.value.items():
            if regex in new_value:
                if sub != new_value[regex]:
                    return
            else:
                new_value[regex] = sub
        return Path(new_value)
    
    def filter(self, predicate: Callable) -> Path:
        return Path({r: self.value[r] for r in self.value if predicate(r)})
    
    def __len__(self) -> int:
        return len(self.value)
    
    def __str__(self) -> str:
        result = []
        for regex, sub in self.value.items():
            result.append(f"{[regex]}: {sub}")
        return ", ".join(result)
            

def update_storage(
    storage: Dict[str, Set[Path]],
    other: Dict[str, Set[Path]]):
    for prefix, paths in other.items():
        if prefix in storage:
            storage[prefix].update(paths)
        else:
            storage[prefix] = paths


def intersect_storages(
    s1: Dict[str, Set[Path]],
    s2: Dict[str, Set[Path]]) -> Dict[str, Set[Path]]:
    storage = {}
    for prefix, paths in s1.items():
        if prefix in s2:
            storage[prefix] = set()
            for p1 in paths:
                for p2 in s2[prefix]:
                    new_path = p1.merge(p2)
                    if new_path is not None:
                        storage[prefix].add(new_path)
            if len(storage[prefix]) == 0:
                del storage[prefix]
    return storage


def priority_concat_storeges(
    prefix_set: Dict[str, Set[Path]],
    suffix_set: Dict[str, Set[Path]]) -> Dict[str, Set[Path]]:
    storage = {}
    for prefix, p_paths in prefix_set.items():
        for suffix, s_paths in suffix_set.items():
            word = prefix + suffix
            paths = set()
            for p in p_paths:
                for s in s_paths:
                    new_value = {k: v for k, v in p.value.items()}
                    new_value.update(s.value)
                    path = Path(new_value)
                    # path = p.merge(s)
                    if path is not None:
                        paths.add(path)
            if len(paths) > 0:
                if word in storage:
                    storage[word].update(paths)
                else:
                    storage[word] = paths
    return storage


def concat_storeges(
    prefix_set: Dict[str, Set[Path]],
    suffix_set: Dict[str, Set[Path]]) -> Dict[str, Set[Path]]:
    storage = {}
    for prefix, p_paths in prefix_set.items():
        for suffix, s_paths in suffix_set.items():
            word = prefix + suffix
            paths = set()
            for p in p_paths:
                for s in s_paths:
                    path = p.merge(s)
                    if path is not None:
                        paths.add(path)
            if len(paths) > 0:
                if word in storage:
                    storage[word].update(paths)
                else:
                    storage[word] = paths
    return storage


def add_to_storage(storage: Dict[str, Set[Path]], word: str, path: Path):
    if word in storage:
        storage[word].add(path)
    else:
        storage[word] = {path}


def merge_to_storage(storage: Dict[str, Set[Path]], regex: Regex, sub: Any):
    for paths in storage.values():
        for path in paths:
            path.add(regex, sub)


def product_storages(
    prefix_set: Dict[str, Set[Path]],
    suffix_set: Dict[str, Set[Path]],
    regex: StarRegex,
    inverse: bool = False) -> Dict[str, Set[Path]]:
    storage = {}
    for prefix, p_paths in prefix_set.items():
        for suffix, s_paths in suffix_set.items():
            word = prefix + suffix
            paths = set()
            for p in p_paths:
                for s in s_paths:
                    new_value = {k: v for k, v in p.value.items()}
                    new_value.update(s.value)
                    if regex in new_value:
                        if inverse:
                            new_value[regex].append(prefix)
                        else:
                            new_value[regex] = [prefix] + new_value[regex]
                    else:
                        new_value[regex] = [prefix]
                    path = Path(new_value)
                    if path is not None:
                        paths.add(path)
            if len(paths) > 0:
                if word in storage:
                    storage[word].update(paths)
                else:
                    storage[word] = paths
    return storage


def copy_to_storage(storage: Dict[str, Set[Path]], copies: Dict[Regex, Regex]):

    def copy_value(path_dict: Dict[Regex, Any], origin: Regex) -> Any:
        if isinstance(origin, ConcatenationRegex):
            return origin
        elif isinstance(origin, BackrefRegex):
            return copy_value(path_dict, origin.regex_value)
        else:
            return path_dict[origin] if origin in path_dict else None

    for paths in storage.values():
        for path in paths:
            path_dict = path.value
            for origin, copy in copies.items():
                result = copy_value(path_dict, origin)
                if result is not None:
                    path_dict[copy] = result


def get_regex_first_k(
    regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
    exact = {} # exac = {"first_k_prefix": {Path(), Path(), ...}}
    sub = {} #  if k > 0 else set("")
    
    if isinstance(regex, BaseRegex):
        if 0 < k <= len(regex):
            result = regex.value
            add_to_storage(exact, result[:k], Path({regex: result}))
    elif isinstance(regex, AlternativeRegex):
        
        for value in regex.value:
            e, s = get_regex_first_k(value, k)

            merge_to_storage(e, regex, value)
            merge_to_storage(s, regex, value)

            update_storage(exact, e)
            update_storage(sub, s)
    elif isinstance(regex, ConcatenationRegex):
        
        if len(regex.value) == 0:
            return exact, sub
        e, s = get_regex_first_k(regex.value[0], k)
        if len(regex.value) == 1:
            update_storage(exact, e)
            update_storage(sub, s)
        else:
            update_storage(sub, e)
            update_storage(sub, s)
            for part in range(k + 1):
                prefix, _ = get_regex_first_k(regex.value[0], part)
                if len(prefix) > 0:
                    
                    suffix_e, suffix_s = get_regex_first_k(regex.sub(1), k - part)
                    update_storage(exact, concat_storeges(prefix, suffix_e))
                    update_storage(sub, concat_storeges(prefix, suffix_s))
    elif isinstance(regex, StarRegex):
        
        if k == 0:
            add_to_storage(exact, "", Path({regex: ""}))
        else:
            value = regex.value
            e, s = get_regex_first_k(value, k)

            merge_to_storage(e, regex, [value])
            merge_to_storage(s, regex, [value])

            update_storage(exact, e)
            update_storage(sub, s)
            for part in range(1, k):
                e, _ = get_regex_first_k(value, part)
                if len(e) > 0:
                    suffix_e, suffix_s = get_regex_first_k(regex, k - part)
                    if len(suffix_e) > 0:
                        update_storage(exact, product_storages(e, suffix_e, regex))
                    if len(suffix_s) > 0:
                        update_storage(sub, product_storages(e, suffix_s, regex))
    else:
        return get_regex_first_k(regex.regex_value, k)
    return exact, sub


def get_regex_last_k(
    regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
    exact = {} # exac = {"first_k_prefix": {Path(), Path(), ...}}
    sub = {} #  if k > 0 else set("")
    if isinstance(regex, BaseRegex):
        if 0 < k <= len(regex):
            result = str(regex)
            add_to_storage(exact, result[-k:], Path({regex: result}))
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            e, s = get_regex_last_k(value, k)

            merge_to_storage(e, regex, value)
            merge_to_storage(s, regex, value)

            update_storage(exact, e)
            update_storage(sub, s)
    elif isinstance(regex, ConcatenationRegex):
        if len(regex.value) == 0:
            return exact, sub
        e, s = get_regex_last_k(regex.value[-1], k)
        if len(regex.value) == 1:
            update_storage(exact, e)
            update_storage(sub, s)
        else:
            update_storage(sub, e)
            update_storage(sub, s)
            for part in range(k + 1):
                suffix, _ = get_regex_last_k(regex.value[-1], part)
                if len(suffix) > 0:
                    
                    prefix_e, prefix_s = get_regex_last_k(regex.sub(end=-1), k - part)
                    update_storage(exact, concat_storeges(prefix_e, suffix))
                    update_storage(sub, concat_storeges(prefix_s, suffix))
    elif isinstance(regex, StarRegex):
        if k == 0:
            add_to_storage(exact, "", Path({regex: ""}))
        else:
            value = regex.value
            e, s = get_regex_last_k(value, k)

            value_copy = copy_regex(value)
            for storage in [e, s]:
                copy_to_storage(storage, value_copy)
                merge_to_storage(storage, regex, [value_copy[value]])
            
            update_storage(exact, e)
            update_storage(sub, s)
            for part in range(1, k):
                e, _ = get_regex_last_k(value, part)
                if len(e) > 0:
                    prefix_e, prefix_s = get_regex_last_k(regex, k - part)
                    if len(prefix_e) > 0:
                        update_storage(exact, product_storages(prefix_e, e, regex, inverse=True))
                    if len(prefix_s) > 0:
                        update_storage(sub, product_storages(prefix_s, e, regex, inverse=True))
    else:
        return get_regex_last_k(regex.regex_value, k)
    return exact, sub


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
    elif isinstance(regex, ConcatenationRegex):
        if len(regex.value) == 0:
            regex.substitute("")
            yield ""
        if len(regex.value) == 1:
            for first_child in open_regex(regex.value[0], rec_limit):
                regex.substitute(first_child)
                yield first_child
        else:
            for first_child in open_regex(regex.value[0], rec_limit):
                for last_child in open_regex(ConcatenationRegex(regex.value[1:]), rec_limit):
                    regex.substitute(first_child + last_child)
                    yield first_child + last_child
    elif isinstance(regex, StarRegex):
        values = list(set(v for v in open_regex(regex.value, rec_limit - 1)))
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


def reopen_regex(
    regex: Regex,
    memory: Dict[Regex, Any],
    rec_limit: int = 1) -> Iterator[str]:
    
    if isinstance(regex, BaseRegex):
        regex_str = memory[regex] if regex in memory else str(regex)
        regex.substitute(regex_str)
        yield regex_str
    elif isinstance(regex, AlternativeRegex):
        if regex in memory:
            for value in reopen_regex(memory[regex], memory, rec_limit):
                regex.substitute(value)
                yield value
        else:
            for value in regex.value:
                for child in reopen_regex(value, memory, rec_limit):
                    regex.substitute(child)
                    yield child
    elif isinstance(regex, ConcatenationRegex):
        if len(regex.value) == 0:
            regex.substitute("")
            yield ""
        if len(regex.value) == 1:
            for first_child in reopen_regex(regex.value[0], memory, rec_limit):
                regex.substitute(first_child)
                yield first_child
        else:
            for first_child in reopen_regex(regex.value[0], memory, rec_limit):
                for last_child in reopen_regex(ConcatenationRegex(regex.value[1:]), memory, rec_limit):
                    regex.substitute(first_child + last_child)
                    yield first_child + last_child
    elif isinstance(regex, StarRegex):
        if rec_limit == 0:
            return
        if regex in memory:
            mem_value = memory[regex]
            if isinstance(mem_value, str):
                regex.substitute(mem_value)
                yield mem_value
            else:
                if isinstance(mem_value[-1], Regex):
                    for value in reopen_regex(mem_value[-1], memory, rec_limit - 1):
                        
                        word = "".join(mem_value[:-1]) + value
                        regex.substitute(word)
                        yield word
                else:
                    for value in reopen_regex(mem_value[0], memory, rec_limit - 1):
                        word = value + "".join(mem_value[1:])
                        regex.substitute(word)
                        yield word
        else:
            values = list(set(v for v in reopen_regex(regex.value, memory, rec_limit - 1)))
            for limit in range(rec_limit):
                for permutation in product(values, repeat=limit):
                    permutation = "".join(permutation)
                    regex.substitute(permutation)
                    yield permutation
    else:
        if regex.regex_value.substitution is not None:
            regex.substitute(regex.regex_value.substitution)
            yield regex.substitution
        else:
            for parent_sub in reopen_regex(regex.regex_value, memory, rec_limit):
                regex.substitute(parent_sub)
                yield parent_sub


def get_n_neighborhood(start_regex: Regex, end_regex: Regex, n: int, k: int) -> Dict[str: List[Path]]:
    if n == 0:
        suffix, s_saffix = get_regex_first_k(end_regex, k)
        update_storage(suffix, s_saffix)
        neighborhood = suffix
    elif n != k:
        prefix, s_prefix = get_regex_last_k(start_regex, n)
        suffix, s_saffix = get_regex_first_k(end_regex, k - n)
        update_storage(prefix, s_prefix)
        update_storage(suffix, s_saffix)
        neighborhood = priority_concat_storeges(prefix, suffix)
    else:  
        prefix, s_prefix = get_regex_last_k(start_regex, n)
        update_storage(prefix, s_prefix)
        neighborhood = prefix
    return neighborhood


def get_zero_neighborhood(regex: Regex, k: int) -> Dict[str: Set[Path]]:
    neighborhood = {}
    if isinstance(regex, BaseRegex):
        value = regex.value
        for i in range(len(regex) - k + 1):
            add_to_storage(neighborhood, value[i:i + k], Path({regex: value}))
    elif isinstance(regex, AlternativeRegex):
        for value in regex.value:
            update_storage(neighborhood, get_zero_neighborhood(value, k))
    elif isinstance(regex, ConcatenationRegex):
        for i, value in enumerate(regex.value[:-1]):
            for n in range(1, k + 1):
                update_storage(neighborhood, get_n_neighborhood(value, regex.sub(start=i + 1), n, k))
        update_storage(neighborhood, get_zero_neighborhood(regex.value[-1], k))
    else: # if isinstance(regex, StarRegex):
        for n in range(k + 1):
            update_storage(neighborhood, get_n_neighborhood(regex, regex, n, k))
    return neighborhood

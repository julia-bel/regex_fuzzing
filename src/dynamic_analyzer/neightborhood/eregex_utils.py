from __future__ import annotations
from typing import Iterator, Tuple, Dict, Optional, List, Any, Set, Callable
from itertools import product
from copy import deepcopy
from json import dumps

from src.eregex.regex import (
    Regex, BaseRegex, StarRegex,
    AlternativeRegex, ConcatenationRegex)


class Path:
    """Container of {Regex: substitution, ...}"""
    def __init__(self, value: Dict[Regex, Any]) -> None:
        self.value = value

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Path) and other.value == self.value
    
    def __hash__(self) -> int:
        # print("DICT")
        # print(self.value)
        json_dict = {hash(r): hash(v) if isinstance(v, Regex) else v \
            for r, v in self.value.items()}
        # print(json_dict)
        return hash(dumps(json_dict, sort_keys=True))
    
    def add(self, regex: Regex, sub: Any):
        self.value[regex] = sub

    def merge(self, other: Path) -> Optional[Path]:
        new_value = deepcopy(other.value)
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
            storage_paths = storage[prefix] = set()
            for p1 in paths:
                for p2 in s2[prefix]:
                    new_path = p1.merge(p2)
                    if new_path is not None:
                        storage_paths.add(new_path)
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
            if word in storage:
                storage[word].update(paths)
            else:
                storage[word] = paths
    return storage


def add_to_storage(storage: Dict[str, Set[Path]], word: str, path: Path):
    if word in storage:
        storage[word].add(path)
    else:
        print(storage)
        print({path})
        storage[word] = {path}

def merge_to_storage(storage: Dict[str, Set[Path]], regex: Regex, sub: Any):
    for paths in storage.values():
        for path in paths:
            path.add(regex, sub)

def product_storages(
    prefix_set: Dict[str, Set[Path]],
    suffix_set: Dict[str, Set[Path]],
    regex: StarRegex) -> Dict[str, Set[Path]]:
    storage = {}
    for prefix, p_paths in prefix_set.items():
        for suffix, s_paths in suffix_set.items():
            word = prefix + suffix
            paths = set()
            for p in p_paths:
                for s in s_paths:
                    path = Path(dict(p.value, **s.value))
                    if path is not None:
                        paths.add(path)
            if word in storage:
                storage[word].update(paths)
            else:
                storage[word] = paths
    return storage


# def product_storage(
#     storage: Dict[str, Set[Path]],
#     repeat: int,
#     regex: StarRegex,
#     suffix_value: Optional[Regex] = None,
#     suffix_storage: Optional[Dict[str, Set[Path]]] = None) -> Dict[str, Set[Path]]:

#     def product_paths(paths: List[Set[Path]]) -> Set[Path]:
#         new_paths = set()
#         if len(paths) > 1:
#             for p1 in paths[0]:
#                 for p2 in product_paths(paths[1:]):
#                     new_path = Path(dict(p1.filter(lambda r: r.group).value, **p2.value))
#                     if len(new_path) > 0:
#                         new_paths.add(new_path)
#         else:
#             for p1 in paths[0]:
#                 new_path = p1.filter(lambda r: r.group)
#                 if len(new_path) > 0:
#                     new_paths.add(new_path)
#         return new_paths

#     new_storage = {}
#     if suffix_storage is not None:
#         for items in product(storage.keys(), repeat=repeat):
#             for suffix in suffix_storage:
#                 word = "".join(items) + suffix
#                 paths = product_paths([storage[item] for item in items])
#                 paths = set(Path(dict(p.value, **sp.value))
#                     for p in paths for sp in suffix_storage[suffix])
#                 for path in paths:
#                     path.add(regex, (word, suffix_value))
#                 if word in new_storage:
#                     new_storage[word].update(paths)
#                 else:
#                     new_storage[word] = paths
#     else:
#         for items in product(storage.keys(), repeat=repeat):
#             word = "".join(items)
#             paths = product_paths([storage[item] for item in items])
#             for path in paths:
#                 path.add(regex, word)
#             if word in new_storage:
#                 new_storage[word].update(paths)
#             else:
#                 new_storage[word] = paths
#     return new_storage


# def inv_product_storage(
#     storage: Dict[str, Set[Path]],
#     repeat: int,
#     regex: StarRegex,
#     suffix_value: Optional[Regex] = None,
#     prefix_storage: Optional[Dict[str, Set[Path]]] = None) -> Dict[str, Set[Path]]:

#     def product_paths(paths: List[Set[Path]]) -> Set[Path]:
#         new_paths = set()
#         if len(paths) > 1:
#             for p1 in paths[0]:
#                 for p2 in product_paths(paths[1:]):
#                     new_path = Path(dict(p1.filter(lambda r: r.group).value, **p2.value))
#                     if len(new_path) > 0:
#                         new_paths.add(new_path)
#         else:
#             for p1 in paths[0]:
#                 new_path = p1.filter(lambda r: r.group)
#                 if len(new_path) > 0:
#                     new_paths.add(new_path)
#         return new_paths

#     new_storage = {}
#     for items in product(storage.keys(), repeat=repeat):
#         for prefix in prefix_storage:
#             word = prefix + "".join(items)
#             paths = product_paths([storage[item] for item in items])
#             paths = set(Path(dict(pp.value, **p.value))
#                 for p in paths for pp in prefix_storage[prefix])
#             for path in paths:
#                 path.add(regex, (word, suffix_value))
#             if word in new_storage:
#                 new_storage[word].update(paths)
#             else:
#                 new_storage[word] = paths
#     return new_storage


def get_regex_first_k(
    regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
    exact = {} # exac = {"first_k_prefix": {Path(), Path(), ...}}
    sub = {} #  if k > 0 else set("")
    print(f"FIRST {k} OF REGEX: {regex}")
    if isinstance(regex, BaseRegex):
        print("BASE")
        if k <= len(regex):
            result = str(regex)
            add_to_storage(exact, result[:k], Path({regex: result}))
    elif isinstance(regex, AlternativeRegex):
        print("ALT")
        for value in regex.value:
            e, s = get_regex_first_k(value, k)

            merge_to_storage(e, regex, value)
            merge_to_storage(s, regex, value)

            update_storage(exact, e)
            update_storage(sub, s)
    elif isinstance(regex, ConcatenationRegex):
        print("CONCATEN")
        if len(regex.value) == 0:
            return exact, sub
        e, s = get_regex_first_k(regex.value[0], k)
        if len(regex.value) == 1:
            print("CONCAT")
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
        print("STAR")
        if k == 0:
            print("ZERO")
            add_to_storage(exact, "", Path({regex: ""}))
        else:
            value = regex.value
            e, s = get_regex_first_k(value, k)

            merge_to_storage(e, regex, value)
            merge_to_storage(s, regex, value)

            update_storage(exact, e)
            update_storage(sub, s)
            for part in range(1, k):
                e, _ = get_regex_first_k(regex.value, part)
                suffix_e, suffix_s = get_regex_first_k(regex, k - part)
                update_storage(exact, product_storages(e, suffix_e))
                update_storage(sub, product_storages(e, suffix_s))

                # if part != 0 and len(e) > 0:
                #     for i in range(1, k // part + 1):
                #         mod = k - i * part
                #         if mod == 0:
                #             update_storage(exact, product_storage(e, i, regex))
                #         else:
                #             ex, s = get_regex_first_k(regex.value, mod)
                #             update_storage(ex, s)
                #             update_storage(exact, product_storage(e, i, regex, regex.value, ex))
                #             print(f"SUB FIRST: {exact} {sub}")
    else:
        return get_regex_first_k(regex.regex_value, k)
    return exact, sub


def get_regex_last_k(
    regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
    exact = {} # exac = {"first_k_prefix": {Path(), Path(), ...}}
    sub = {} #  if k > 0 else set("")
    print(f"LAST OF REGEX: {regex}")
    if isinstance(regex, BaseRegex):
        print("BASE")
        if k <= len(regex):
            result = str(regex)
            add_to_storage(exact, result[-k:], Path({regex: result}))
    elif isinstance(regex, AlternativeRegex):
        print("ALT")
        for value in regex.value:
            e, s = get_regex_last_k(value, k)

            merge_to_storage(e, regex, value)
            merge_to_storage(s, regex, value)

            update_storage(exact, e)
            update_storage(sub, s)
    elif isinstance(regex, ConcatenationRegex):
        print("CONCATEN")
        if len(regex.value) == 0:
            return exact, sub
        e, s = get_regex_last_k(regex.value[-1], k)
        if len(regex.value) == 1:
            print("CONCAT")
            update_storage(exact, e)
            update_storage(sub, s)
        else:
            update_storage(sub, e)
            update_storage(sub, s)
            inv_regex = ConcatenationRegex(regex.value[::-1])
            for part in range(k + 1):
                suffix, _ = get_regex_last_k(inv_regex.value[0], part)
                prefix_e, prefix_s = get_regex_last_k(inv_regex.sub(1), k - part)
                update_storage(exact, concat_storeges(prefix_e, suffix))
                update_storage(sub, concat_storeges(prefix_s, suffix))
    elif isinstance(regex, StarRegex):
        print("STAR")
        if k == 0:
            print("ZERO")
            add_to_storage(exact, "", Path({regex: ""}))
        else:
            value = regex.value
            e, s = get_regex_last_k(value, k)

            merge_to_storage(e, regex, value)
            merge_to_storage(s, regex, value)

            update_storage(exact, e)
            update_storage(sub, s)
            for part in range(1, k):
                e, _ = get_regex_first_k(regex.value, part)
                suffix_e, suffix_s = get_regex_first_k(regex, k - part)
                update_storage(exact, product_storages(e, suffix_e))
                update_storage(sub, product_storages(e, suffix_s))
            # for part in range(1, k):
            #     e, s = get_regex_last_k(regex.value, part)
            #     if part != 0 and len(e) > 0:
            #         for i in range(1, k // part + 1):
            #             mod = k - i * part
            #             if mod == 0:
            #                 update_storage(exact, product_storage(e, i, regex))
            #             else:
            #                 ex, s = get_regex_last_k(regex.value, mod)
            #                 update_storage(ex, s)
            #                 update_storage(exact, inv_product_storage(e, i, regex, regex.value, ex))
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
        regex.substitute(None)
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
        regex.substitute(None)
    elif isinstance(regex, StarRegex):
        if regex in memory:
            mem_value = memory[regex]
            if isinstance(mem_value, str):
                regex.substitute(mem_value)
                yield mem_value
            else:
                for value in reopen_regex(mem_value[1], memory, rec_limit):
                    regex.substitute(mem_value[0] + value)
                    yield mem_value[0] + value
        else:
            values = list(set(v for v in reopen_regex(regex.value, rec_limit)))
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
            for parent_sub in reopen_regex(regex.regex_value, memory, rec_limit):
                regex.substitute(regex.regex_value.substitution)
                yield parent_sub

   
# def get_regex_last_k(regex: Regex, k: int) -> Tuple[Dict[str: List[Path]], Dict[str: List[Path]]]:
#     exact, sub = get_regex_first_k(regex.reverse(), k)
#     exact = {e[::-1]: v for e, v in exact.items()}
#     sub = {s[::-1]: v for s, v in sub.items()}
#     return exact, sub


def get_n_neighborhood(start_regex: Regex, end_regex: Regex, n: int, k: int) -> Dict[str: List[Path]]:
    print(f"N_NEGH_FUNC of {start_regex} {end_regex}")
    if n == 0:
        print("N = 0")
        suffix, s_saffix = get_regex_first_k(end_regex, k)
        update_storage(suffix, s_saffix)
        neighborhood = suffix
        print(neighborhood)
        print("END")
    elif n != k:
        print(f"N = {n}, K = {k}")
        prefix, s_prefix = get_regex_last_k(start_regex, n)
        suffix, s_saffix = get_regex_first_k(end_regex, k - n)
        update_storage(prefix, s_prefix)
        update_storage(suffix, s_saffix)
        neighborhood = concat_storeges(prefix, suffix)
    else:
        print(f"N = K = {k}")
        prefix, s_prefix = get_regex_last_k(start_regex, n)
        update_storage(prefix, s_prefix)
        neighborhood = prefix
    
    return neighborhood


def get_zero_neighborhood(regex: Regex, k: int) -> Dict[str: Set[Path]]:
    print(f"ZERO NEIGH of regex: {regex} k: {k}")
    print(f"reg g: {regex.group}")
    print(regex.value)
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
            a = get_n_neighborhood(regex, regex, n, k)
            print(f"N_NEIGH: {a} {n}")
            print(neighborhood)
            # for p, pp in a.items():
            #     print("-" * 20 + p + "-" * 20)
            #     for s in pp:
            #         for i, ii  in s.value.items():
            #             print(type(i))
            #             print(f"{i}: {ii}")
            #     print("-" * 20 + p + "-" * 20)
            update_storage(neighborhood, get_n_neighborhood(regex, regex, n, k))
            print("updated")
            print(neighborhood)
    # print(f"neighborhood: {neighborhood}")
    # for n, v in neighborhood.items():
    #     for p in v:
    #         print("-" * 20)
    #         for i, ii  in p.value.items():
    #             print(type(i))
    #             print(f"{i}: {ii}")
    # print("-" * 20)
    return neighborhood

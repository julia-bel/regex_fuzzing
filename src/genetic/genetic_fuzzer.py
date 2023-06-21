from typing import Tuple, List, Callable, Optional, Set
from random import randint, choice, sample, choices
from copy import deepcopy
import numpy as np


def softmax(x: List[float]) -> np.ndarray:
    e_x = np.exp(x - np.max(x))
    return e_x / e_x.sum(axis=0)


class GeneticFuzzer:
    """Genetic fuzzing implementation"""

    def __init__(self, weights: Optional[List[float]] = None):
        self.vocab = []
        self.generation = []
        self.mutations = [
            self.append,
            self.insert,
            self.delete,
            self.replicate,
            self.reverse,
            self.cyclic_shift,
        ]
        if weights is None:
            weights = [0.9, 0.6, 0.7, 0.5, 0.5, 0.8]
        self.set_weights(weights)

    def set_weights(self, weights: List[float]):
        assert len(weights) == len(self.mutations), "incorrect weights"
        self.weights = softmax(weights)

    def cast(
        self,
        parents: Set[str],
        vocab: List[str],
        binary_func: Callable,
        num_epochs: int = 30,
        min_iters: int = 20,
        mutations_range: List[int] = [1, 2]) -> Optional[str]:
        """Selecting strings that match a binary function

        Args:
            parents (str): base words for mutation.
            binary_func (Callable): binary selection function.
            num_epochs (int, optional): defaults to 10.
            min_iters (int): min number of base words in epoch. Defaults to 20.
            mutations_range (List[int]): range of the amount of mutations to use. Defaults to [1, 2].

        Returns:
            List[str]: mutation results.
        """
        self.vocab = vocab
        base = deepcopy(parents)
        mutations_idxs = range(len(self.mutations))

        for _ in range(num_epochs):
            delta = min_iters - len(base)
            for parent in parents:
                if parent not in base:
                    base.add(parent)
                    delta -= 1
                if delta == 0:
                    break
            new_base = set()
            for word in base:
                mutation_indexes = choices(
                    mutations_idxs,
                    weights=self.weights,
                    k=randint(*mutations_range))
                for i in mutation_indexes:
                    word = self.mutations[i](word)
                    if binary_func(word):
                        return word
                new_base.add(word)
            base = new_base
    
    def cast_population(
        self,
        parents: List[str],
        vocab: List[str],
        binary_func: Callable,
        num_epochs: int = 30,
        min_iters: int = 20,
        mutations_range: List[int] = [1, 2]) -> Set[str]:
        """Selecting strings that match a binary function

        Args:
            parents (str): base words for mutation.
            binary_func (Callable): binary selection function.
            num_epochs (int, optional): defaults to 10.
            min_iters (int): min number of base words in epoch. Defaults to 20.
            mutations_range (List[int]): range of the amount of mutations to use. Defaults to [1, 2].

        Returns:
            List[str]: mutation results.
        """
        result = set()
        self.vocab = vocab
        base = deepcopy(parents)
        mutations_idxs = range(len(self.mutations))

        for _ in range(num_epochs):
            delta = min_iters - len(base)
            for parent in parents:
                if parent not in base:
                    base.add(parent)
                    delta -= 1
                if delta == 0:
                    break
            new_base = set()
            for word in base:
                mutation_indexes = choices(
                    mutations_idxs,
                    weights=self.weights,
                    k=randint(*mutations_range))
                for i in mutation_indexes:
                    word = self.mutations[i](word)
                    if binary_func(word):
                        result.add(word)
                        self.weights[i] += 0.1
                        self.weights = softmax(self.weights)
                new_base.add(word)
            base = new_base
        return result
        
    def cross_over(
        self,
        string_1: str,
        string_2: str,
        chars_range: List[int] = [1, 3]) -> Tuple[str, str]:
        """Random substring exchange

        Args:
            string_1 (str): input.
            string_2 (str): input.
            chars_range (List[int], optional): defines amount of chars to exchange. 
                Defaults to [1, 3].

        Returns:
            Tuple[str, str]: result.
        """
        num_chars = min([len(string_1), len(string_2), randint(*chars_range)])
        offset_1 = randint(0, len(string_1) - num_chars)
        offset_2 = randint(0, len(string_2) - num_chars)
        result_1 = string_1[:offset_1] + string_2[offset_2:offset_2 + num_chars] + \
            string_1[offset_1 + num_chars:]
        result_2 = string_2[:offset_2] + string_1[offset_1:offset_1 + num_chars] + \
            string_2[offset_2 + num_chars:]
        return result_1, result_2
    
    def append(self, string: str) -> str:
        part = choice(self.vocab)
        result = string + part if choice([0, 1]) else part + string
        return result
    
    def insert(self, string: str) -> str:     
        sub = choice(self.vocab)
        new_string = list(string)
        new_string.insert(randint(0, len(string)), sub)
        result = ''.join(new_string)
        return result
    
    def delete(self, string: str, del_range: List[int] = [1, 3]) -> str:
        """Random deletion of substring

        Args:
            string (str): input.
            del_range (List[int], optional): defines amount of chars to delete. Defaults to [1, 3].

        Returns:
            str: result.
        """
        if len(string) == 0:
            return string
        offset = randint(0, len(string) - 1)
        result = string[:offset] + string[offset + randint(*del_range):]
        return result
    
    def replicate(
        self,
        string: str,
        chars_range: List[int] = [1, 3],
        rep_range: List[int] = [1, 3]) -> str:
        """Random replication of substring

        Args:
            string (str): input.
            chars_range (List[int], optional): defines amount of chars to replicate. Defaults to [1, 3].
            rep_range (List[int], optional): defines amount of replications. Defaults to [1, 3].

        Returns:
            str: result.
        """
        if len(string) == 0:
            return string
        chars_num = min(randint(*chars_range), len(string)) 
        offset = randint(0, len(string) - chars_num)
        core = string[offset:offset + chars_num]
        result = string[:offset] + core * randint(*rep_range) + string[offset + chars_num:]
        return result
    
    def reverse(
        self,
        string: str,
        chars_range: List[int] = [1, 3]) -> str:
        """Reverse random substring

        Args:
            string (str): input.
            chars_range (List[int], optional): defines amount of chars to reverse. Defaults to [1, 3].

        Returns:
            str: result.
        """
        if len(string) == 0:
            return string
        chars_num = min(len(string), randint(*chars_range))
        offset = randint(0, len(string) - chars_num)
        core = string[offset:offset + chars_num]
        result = string[:offset] + core[::-1] + string[offset + chars_num:]
        return result
    
    def cyclic_shift(
        self, string: str,
        chars_range: List[int] = [1, 3]) -> str:
        """Cyclic shift of random substring

        Args:
            string (str): input.
            chars_range (List[int], optional): defines amount of chars to shift. Defaults to [1, 3].
        Returns:
            str: result.
        """
        if len(string) == 0:
            return string
        d = min(len(string) - 1, randint(*chars_range))
        if randint(0, 1):
            first = string[0:d]
            second = string[d:]
        else:
            first = string[0:len(string)-d]
            second = string[len(string)-d:]
        return second + first

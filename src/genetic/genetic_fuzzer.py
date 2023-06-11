import numpy as np

from typing import Tuple, Any, List, Callable, Optional
from random import randint, choice, sample, choices


def softmax(x: List[float]):
    e_x = np.exp(x - np.max(x))
    return e_x / e_x.sum(axis=0)


class GeneticFuzzer:
    """Genetic fuzzing implementation"""

    def __init__(self, weights: Optional[List[float]]):
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

    def pump(self, word: str, score_func: Callable) -> List[int]:
        length = len(word)
        max_score = -1
        bounds = [0, 0]
        for i in range(length):
            for j in range(i, length):
                attack = word[:i] + word[i:j] * 2 + word[j:]
                score = score_func(attack)
                if score > max_score:
                    max_score = score
                    bounds = [i, j]
        return bounds
    
    # TODO: evolution
    def evolve(
        self,
        parent: str,
        fitness_func: Callable,
        num_epochs: int = 10) -> Tuple[str, Any]:
        self.vocab = list(parent)
        self.generation = self.vocab
        for _ in num_epochs:
            pass
            # self.next_generation()
        best = np.argmax([fitness_func(elem) for elem in self.generation])
        return best, self.pump(best, fitness_func)
    
    def cast(
        self,
        parents: List[str],
        vocab: List[str],
        binary_func: Callable,
        num_epochs: int = 30,
        min_iters: int = 20,
        mutations_range: List[int] = [1, 2]) -> List[str]:
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
        result = set()
        base = parents
        for _ in num_epochs:
            delta = min_iters - len(base)
            if delta > 0:
                base += sample(base, delta)
            new_base = parents
            for word in base:
                mutation_indexes = choices(
                    range(self.mutations),
                    weights=self.weights,
                    k=randint(*mutations_range))
                for i in mutation_indexes:
                    word = self.mutations[i](word)
                    if binary_func(word):
                        result.add(word)
                        self.weights[i] += 0.1
                        self.weights = softmax(self.weights)
                new_base.append(word)
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
            string_1[offset_1 + num_chars]
        result_2 = string_2[:offset_2] + string_1[offset_1:offset_1 + num_chars] + \
            string_2[offset_2 + num_chars]
        return result_1, result_2
    
    def append(self, string: str) -> str:
        part = choice(self.vocab)
        result = string + part if choice([0, 1]) else part + string
        return result
    
    def insert(self, string: str) -> str:     
        sub = choice(self.vocab)
        result = ''.join(list(string).insert(randint(0, len(string) - 1), sub))
        return result
    
    def delete(self, string: str, del_range: List[int] = [1, 3]) -> str:
        """Random deletion of substring

        Args:
            string (str): input.
            del_range (List[int], optional): defines amount of chars to delete. Defaults to [1, 3].

        Returns:
            str: result.
        """        
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
        chars_num = randint(*chars_range) 
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
        chars_num = min(len(string), randint(*chars_range))
        offset = randint(0, len(string) - chars_num)
        core = string[offset:offset + chars_num]
        result = string[:offset] + core[::-1] + string[offset + chars_num:]
        return result
    
    def cyclic_shift(
        self,
        string: str,
        chars_range: List[int] = [1, 3]) -> str:
        """Cyclic shift of random substring

        Args:
            string (str): input.
            chars_range (List[int], optional): defines amount of chars to shift. Defaults to [1, 3].
        Returns:
            str: result.
        """        
        chars_num = min(len(string), randint(*chars_range))
        offset = randint(0, len(string) - chars_num)
        core = string[offset:offset + chars_num]
        result = string[:offset] + core[-1] + core[:-1] + string[offset + chars_num:]
        return result

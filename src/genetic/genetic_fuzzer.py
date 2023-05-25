from typing import Tuple, Any, List
from random import randint, choice

from src.eregex.abstract_regex import Regex
from src.wrappers.regex_matcher import RegexMatcher


class GeneticFuzzer:
    
    def __init__(
        self,
        matcher: RegexMatcher) -> None:
        self.generation = []
        self.matcher = matcher
        self.mutations = [
            self.insert,
            self.delete,
            self.replicate,
            self.reverse
        ]

    def _generate_dictionary(self, regex: Regex) -> None:
        # TODO: to generate dictionary based on regex structure
        pass

    def execute(self, regex: Regex) -> Any:
        self.dictionary = self._generate_dictionary(regex)
        pass

    def next_generation(self) -> Any:
        # TODO: genetic strategy based on results of fitness function
        for parent in self.generation:
            pass
        
    def cross_over(
        self,
        string_1: str,
        string_2: str,
        chars_range: List[int] = [1, 3]) -> Tuple[str, str]:
        """Random substring exchange

        Args:
            string_1 (str): input
            string_2 (str): input
            chars_range (List[int], optional): defines amount of chars to exchange. 
                Defaults to [1, 3].

        Returns:
            Tuple[str, str]: result
        """        
        num_chars = min([len(string_1), len(string_2), randint(*chars_range)])
        offset_1 = randint(0, len(string_1) - num_chars)
        offset_2 = randint(0, len(string_2) - num_chars)
        result_1 = string_1[:offset_1] + string_2[offset_2:offset_2 + num_chars] + \
            string_1[offset_1 + num_chars]
        result_2 = string_2[:offset_2] + string_1[offset_1:offset_1 + num_chars] + \
            string_2[offset_2 + num_chars]
        return result_1, result_2
    
    def insert(
        self,
        string: str,
        rep_range: List[int] = [1, 3]) -> str:
        """Random insertion of substring from dictionary

        Args:
            string (str): input
            rep_range (List[int], optional): defines amount of replications of dictionary string. 
                Defaults to [1, 3].

        Returns:
            str: result
        """        
        sub = choice(self.dictionary) * randint(*rep_range)
        result = ''.join(list(string).insert(randint(0, len(string) - 1), sub))
        return result
    
    def delete(self, string: str, del_range: List[int] = [1, 3]) -> str:
        """Random deletion of substring

        Args:
            string (str): input
            del_range (List[int], optional): defines amount of chars to delete. Defaults to [1, 3].

        Returns:
            str: result
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
            string (str): input
            chars_range (List[int], optional): defines amount of chars to replicate. Defaults to [1, 3].
            rep_range (List[int], optional): defines amount of replications. Defaults to [1, 3].

        Returns:
            str: result
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
            string (str): input
            chars_range (List[int], optional): defines amount of chars to reverse. Defaults to [1, 3].

        Returns:
            str: result
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
        pass
        return result
    
    def fitness_function(self) -> float:
        # TODO: relative coefficient
        pass
    
    def test(self) -> Any:
        # TODO: match population
        pass

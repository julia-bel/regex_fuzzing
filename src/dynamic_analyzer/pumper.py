from typing import Callable, List
from src.wrappers.regex_matcher import RegexMatcher


class Pumper:
    def __init__(self):
        pass

    def analyze_ambiguity(self, iter: int = 20, step: int = 2):
        pass

    def run(
        self,
        word: str,
        regex: str,
        matcher: RegexMatcher,
        score_func: Callable,
        timeout: float = 0.5,
        max_iter: int = 10) -> List[int]:
        # TODO
        stop = len(word)
        max_score = -1
        bounds = [0, 0]
        for i in range(stop):
            for j in range(i, stop):
                attack = word[:i] + word[i:j] * max_iter + word[j:]
                time = matcher.match(attack, regex, timeout) # pumping format
                score = score_func(time, attack)
                if score > max_score:
                    max_score = score
                    bounds = [i, j]
        return 

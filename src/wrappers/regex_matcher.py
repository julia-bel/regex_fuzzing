import re

from subprocess import PIPE, Popen, TimeoutExpired
from typing import List, Optional, Dict, Iterator, Tuple


JS_MATCHER_PATH = "src/regex_matcher/src/javascript/query-node.js"


class RegexMatcher:
    """Regex Matcher Wrapper"""

    def __init__(self, encoding: str = "utf-8"):
        self.encoding = encoding

    def execute(self, proc: Popen, timeout: int) -> Optional[bytes]:
        try:
            outs, _ = proc.communicate(timeout=timeout)
            return outs
        except TimeoutExpired:
            proc.kill()
            print(f"Timeout: {timeout} in Regex Matcher")

    def parse_result(self, logs: str) -> float:
        return float(re.search(r"\d+\.\d+", logs).group(0))

    def match_word(self, word: str, regex: str, timeout: float = 0.5) -> float:
        proc = Popen([JS_MATCHER_PATH, word, regex], stdout=PIPE)
        outs = self.execute(proc, timeout)
        if outs is not None:
            return self.parse_result(outs.decode(self.encoding))
        return timeout

    def match_group(
        self,
        attack: List[List[str]|str],
        steps: Dict[str, List[int]],
        regex: str,
        timeout: float = 0.5) -> Tuple[List[float], List[int]]:
        # attack: List[List[str]|str], (e.g. [["a", "1"], "b", ["a", "1"]])
        # steps: Dict[str, List[int]], (e.g. {"1": [start, end, step]}, [start, end))
        
        def step_iterator(steps: Dict[str, List[int]]) -> Iterator[Dict[str, int]]:
            min_length = None
            iterable_steps = {}
            for k, v in steps.items():
                step_range = range(*v)
                if min_length is not None:
                    min_length = min(min_length, len(step_range))
                else:
                    min_length = len(step_range)
                iterable_steps[k] = iter(step_range)

            for _ in range(min_length):
                yield {k: next(v) for k, v in iterable_steps.items()}

        times = []
        lengths = []
        for step in step_iterator(steps):
            word = "".join([a if isinstance(a, str) else a[0] * step[a[1]] for a in attack])
            times.append(self.match_word(word, regex, timeout))
            lengths.append(len(word))
        return times, lengths

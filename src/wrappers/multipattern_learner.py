from typing import List, Optional

from src.patterns_learning.main import learn
from src.patterns_learning.pattern.pattern import NEPattern
from src.multipattern.repattern import REPattern


class REPatternLearner:
    """Multipattern Learner Wrapper"""

    def __init__(self):
        pass

    def learn_repattern(self, populations: List[List[str]]) -> REPattern:
        pass

    def learn_pattern(self, corpus: List[str]) -> Optional[NEPattern]:
        return learn(corpus, optimize=True)

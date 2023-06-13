from scipy.optimize import curve_fit
from typing import List
import numpy as np

from src.const import (
    NO_AMBIGUOUS, POLY_AMBIGUOUS, EXP_AMBIGUOUS, 
    LINEAR_FUNC, POLY_FUNC, EXP_FUNC)


class AmbiguityAnalyzer:
    def __init__(self):
        self.fit = lambda x, y, func: curve_fit(func,  x,  y)[0]
        self.functions = {
            NO_AMBIGUOUS: LINEAR_FUNC,
            POLY_AMBIGUOUS: POLY_FUNC,
            EXP_AMBIGUOUS: EXP_FUNC,
        }

    def loss(self, real: List[float], pred: List[float]):
        return sum([(r - p)**2 for r, p in zip(real, pred)]) / len(real)

    def analyze(self, time: List[float], length: List[int]) -> int:
        min_func = -1
        min_loss = None
        for status, func in self.functions.items():
            params = self.fit(length, time, func)
            loss = self.loss(time, [func(l, *params) for l in length])
            if min_loss is None or loss < min_loss:
                min_loss = loss
                min_func = status
        return min_func
    
    # def analyze(self, time: List[float], length: List[int]) -> int:
    #     last_k = time[-1] / length[-1]
    #     mean_k = np.mean(time[-1]) / np.mean(length[-1])
    #     return POLY_AMBIGUOUS if last_k / mean_k > 0.5 else NO_AMBIGUOUS

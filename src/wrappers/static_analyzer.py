from subprocess import PIPE, Popen, TimeoutExpired
from typing import Optional
import re

from src.const import (EXP_AMBIGUOUS, NO_AMBIGUOUS, POLY_AMBIGUOUS)


INTERPRETER_PATH = "src/static_analyzer/build/apps/InterpreterApp/InterpreterApp"
ANALYZER_QUERY = 'X = Ambiguity.Thompson {{{}}}'
QUERY_FILE = "input.txt"


class StaticAnalyzer:
    """Static Analyzer Wrapper"""

    def __init__(self, encoding: str = "utf-8"):
        self.encoding = encoding

    def execute(self, proc: Popen, timeout: float = 2) -> Optional[bytes]:
        try:
            outs, _ = proc.communicate(timeout=timeout)
            return outs
        except TimeoutExpired:
            proc.kill()
            # print(f"Timeout: {timeout} in Static Analyzer")

    def parse_result(self, logs: str) -> int:
        if re.search("(E|e)xponential", logs):
            return EXP_AMBIGUOUS
        if re.search("(P|p)olynomial", logs):
            return POLY_AMBIGUOUS
        return NO_AMBIGUOUS

    def analyze(self, regex: str, timeout: float = 2) -> int:
        with open(QUERY_FILE, "w", encoding=self.encoding) as query:
            query.write(ANALYZER_QUERY.format(regex))
        proc = Popen([INTERPRETER_PATH, QUERY_FILE, "-n"], stdout=PIPE)
        outs = self.execute(proc, timeout)
        if outs is not None:
            return self.parse_result(outs.decode(self.encoding))
        return NO_AMBIGUOUS

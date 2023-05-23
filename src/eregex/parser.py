from re import match

from src.eregex.const import (L_PAR, R_PAR, KLEENE_STAR, ALTERNATIVE, DIGITS, BACKSLASH)
from src.eregex.regex import (BaseRegex, StarRegex, Regex, BackrefRegex, ConcatenationRegex, AlternativeRegex)


class ERegexParser:

    def __init__(self, value: str):
        self.value = list(value[::-1])
        self.opened_parentheses = 0
        self.closed_parentheses = 0
        self.capture_groups = {}

    def peek_char(self) -> str:
        return self.value[-1] if self.value else ""

    def next_char(self) -> str:
        return self.value.pop() if self.value else ""

    def parse(self) -> Regex:

        def add2parsed(regex: str):
            nonlocal parsed
            if regex:
                parsed += [BaseRegex(char) for char in regex]

        parsed = []
        curr_regex = ""
        alternative = 0
        while len(self.value) > 0:
            char = self.next_char()
            if char == L_PAR:
                self.opened_parentheses += 1
                add2parsed(curr_regex)
                curr_regex = ""
                parsed.append(self.parse())
                self.capture_groups[str(self.closed_parentheses)] = parsed[-1]
            elif char == R_PAR:
                self.closed_parentheses += 1
                assert self.closed_parentheses <= self.opened_parentheses, "invalid parentheses"
                add2parsed(curr_regex)
                if alternative:
                    assert len(parsed) > alternative, "invalid alternative expression"
                    if len(parsed) != alternative + 1:
                        parsed = parsed[:alternative] + [ConcatenationRegex(parsed[alternative:], group=True)]
                    return AlternativeRegex(parsed, group=True)
                return ConcatenationRegex(parsed, group=True)
            elif char == ALTERNATIVE:
                add2parsed(curr_regex)
                curr_regex = ""
                assert len(parsed) > alternative, "invalid alternative expression"
                if len(parsed) != alternative + 1:
                    parsed = parsed[:alternative] + [ConcatenationRegex(parsed[alternative:])]
                alternative += 1
            elif char == KLEENE_STAR:
                if curr_regex:
                    add2parsed(curr_regex[:-1])
                    parsed.append(StarRegex(BaseRegex(curr_regex[-1])))
                    curr_regex = ""
                else:
                    assert len(parsed) > 0, "invalid operation"
                    parsed[-1] = StarRegex(parsed[-1])
            elif char == BACKSLASH:
                digits = ""
                while match(DIGITS, self.peek_char()):
                    digits += self.next_char()
                if digits != "":
                    assert digits in self.capture_groups, "invalid capture group"
                    add2parsed(curr_regex)
                    parsed.append(BackrefRegex(BACKSLASH + digits, self.capture_groups[digits]))
                    curr_regex = ""
                else:
                    curr_regex += char
            else:
                curr_regex += char
        assert self.closed_parentheses == self.opened_parentheses, "invalid parentheses"
        add2parsed(curr_regex)
        if alternative:
            assert len(parsed) > alternative, "invalid alternative expression"
            if len(parsed) != alternative + 1:
                parsed = parsed[:alternative] + [ConcatenationRegex(parsed[alternative:])]
            return AlternativeRegex(parsed)
        return parsed[0] if len(parsed) == 1 else ConcatenationRegex(parsed)

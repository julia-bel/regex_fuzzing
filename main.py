from typing import Dict, Optional
import argparse

from src.const import POLY_AMBIGUOUS
from src.wrappers.static_analyzer import StaticAnalyzer
from src.genetic.genetic_fuzzer import GeneticFuzzer
from src.multipattern.remultipattern import REMultipattern
from src.dynamic_analyzer.fuzzer.pattern_fuzzer import REPatternFuzzer
from src.dynamic_analyzer.fuzzer.eregex_fuzzer import ERegexFuzzer
from src.eregex.parser import ERegexParser
from src.dynamic_analyzer.ambiguity_analyzer import AmbiguityAnalyzer
from src.wrappers.regex_matcher import RegexMatcher

from src.eregex.abstract_regex import Regex
from src.eregex.regex import (BaseRegex, BackrefRegex, ConcatenationRegex)
from src.multipattern.repattern import REPattern, REVariable


def regex_to_pattern(regex: Regex) -> Optional[REPattern]:
    if isinstance(regex, BaseRegex):
        return REPattern([regex.value])
    elif isinstance(regex, ConcatenationRegex):
        pattern = []
        vars = {}
        for elem in regex.value:
            if isinstance(elem, BaseRegex):
                pattern.append(str(elem))
            elif isinstance(elem, BackrefRegex):
                pattern.append(vars[elem.regex_value])
            else:
                pattern.append(REVariable(elem))
                vars[elem] = pattern[-1]
        return REPattern(pattern)


def log(ambs: Dict[int, REMultipattern]):
    if len(ambs) == 0:
        print("No ambiguity found")
        return
    for k, v in ambs.items():
        print("Found: " + "polynomial" if k == POLY_AMBIGUOUS else "exponential")
        print("Pumping pattern:\n" + str(v))


def main(
    value: str,
    radius: int = 10,
    timeout: float = 0.5,
    first: bool = True,
    pattern: bool = False,
    visualize: bool = False):

    genetic = GeneticFuzzer()
    matcher = RegexMatcher()
    analyzer = StaticAnalyzer()
    ambiguity_analyzer = AmbiguityAnalyzer()

    value = ERegexParser(value).parse()
    if len(visualize) > 0:
        value.plot().render(visualize, format="png")
    if pattern:
        fuzzer = REPatternFuzzer(genetic, matcher, analyzer, ambiguity_analyzer)
        value = regex_to_pattern(value)
        assert value is not None, "incorrect pattern"
    else:
        fuzzer = ERegexFuzzer(genetic, matcher, analyzer, ambiguity_analyzer)
    log(fuzzer.run(value, radius, timeout, first))


if __name__ == "__main__":
    base_examples = ["a(a*)\\1", "bcaa(c*)cccc\\1", "a(a*)(b|a)*a\\1"]

    parser = argparse.ArgumentParser(
        description='''Dynamic complexity analysis of regular expressions and re-patterns''')
    parser.add_argument('value', help='value to analyze')
    parser.add_argument(
        '-v', '--visualize',
        action='store',
        default='',
        type=str,
        help='path to file for structure visualization')
    parser.add_argument(
        '-t', '--timeout',
        action='store',
        default=0.5,
        type=float,
        help='timeout for matching')
    parser.add_argument(
        '-r', '--radius',
        action='store',
        type=int,
        default=10,
        help='max radius for neighborhood extension')
    parser.add_argument(
        '-p', '--pattern',
        action='store_true',
        help='re-pattern mode')
    parser.add_argument(
        '-f', '--first',
        action='store_true',
        help='whether to show first vulnerability')
    args = parser.parse_args()
    
    main(
        value=args.value,
        pattern=args.pattern,
        timeout=args.timeout,
        radius=args.radius,
        first=args.first,
        visualize=args.visualize)

    # module testing
    # parser = ERegexParser('((ss)*)\\1\\2b')
    # res = parser.parse()
    # res.plot().render(f"visualization/regex.gv", format="png").replace('\\', '/')
    # print([str(v.regex_value) for v in res.value if isinstance(v, BackrefRegex)])

    # analyzer = StaticAnalyzer()
    # print(analyzer.analyze('(a*)*'))
    
    # matcher = RegexMatcher()
    # print(matcher.match_group([["a", "1"], "b"], {"1": [0, 30, 5]}, "a*a*"))

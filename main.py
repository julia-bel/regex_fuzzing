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


def log(ambs: Optional[Dict[int, REMultipattern]] = None):
    if ambs is None or len(ambs) == 0:
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
    genetic: bool = False,
    rec_limit: int = 3,
    visualize: bool = False):

    matcher = RegexMatcher()
    analyzer = StaticAnalyzer()
    ambiguity_analyzer = AmbiguityAnalyzer()

    value = ERegexParser(value).parse()
    if len(visualize) > 0:
        value.plot().render(visualize, format="png")
    # TODO: try...except
    # try:
    if pattern:
        fuzzer = REPatternFuzzer(GeneticFuzzer(), matcher, analyzer, ambiguity_analyzer)
        log(fuzzer.run(
            value,
            max_radius=radius,
            timeout=timeout,
            genetic=genetic,
            rec_limit=rec_limit,
            first=first))
    else:
        fuzzer = ERegexFuzzer(matcher, analyzer, ambiguity_analyzer)
        # log(fuzzer.run(
        #     value,
        #     max_radius=radius,
        #     timeout=timeout,
        #     rec_limit=rec_limit,
        #     first=first))
    # except:
    #     log()

if __name__ == "__main__":
    # i = pump_suffix("ab", "baba")
    # print("ab"[:i], "ab"[i:])
    base_examples = ["a(a*)\\1", "bcaa(c*)cccc\\1", "a(a*)(b|a)*a\\1"]
    from src.dynamic_analyzer.neightborhood.pattern_utils import get_regex_first_k

    regex = ERegexParser("(ab)*").parse()
    print(get_regex_first_k(regex, 5))

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
        default=2,
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
        '-g', '--genetic',
        action='store_true',
        help='whether to use genetic algorithms for pattern analysis')
    parser.add_argument(
        '-d', '--depth',
        default=3,
        type=int,
        help='limit for recursive opening of regexes')
    parser.add_argument(
        '-f', '--first',
        action='store_true',
        help='whether to show first vulnerability')
    args = parser.parse_args()
    
    main(
        value=args.value,
        pattern=args.pattern,
        timeout=args.timeout,
        rec_limit=args.depth,
        genetic=args.genetic,
        radius=args.radius,
        first=args.first,
        visualize=args.visualize)

    # "(ba)*b(ab)*"
    # "(a*)aaaa\\1"
    # "((ba)*)aaa(ab)*a\\1"
    # "(a*b*)aaaaab*b\\1"

    import numpy as np
    matcher = RegexMatcher()
    regex = '(a*b*)aaaaab*b\\1'
    attack = {'prefix': "", 'pump': 'aaaaabbb', 'suffix': 'h'}
    ts = []
    ls = []
    for n in range(1, 100, 10):
        word = attack['prefix'] + attack['pump'] * n + attack['suffix']
        ls.append(len(word))
        ts.append(matcher.match_word(word, "(" + regex + ")", timeout=2))
    
    word = attack['prefix'] + attack['pump'] * 500 + attack['suffix']
    print((ts[-1] / ls[-1]) / (np.mean(ts) / np.mean(ls)))

    

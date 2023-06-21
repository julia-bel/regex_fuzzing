from typing import Dict, Optional, List
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


def test(index: str, path: str, encoding="utf8") -> List[str]:
    preprocess = lambda x: x.rstrip("\n").replace("\\\\", "\\")
    with open(path, "r", encoding=encoding) as file:
        if index == "-1":
            test = [preprocess(line) for line in file.readlines()]
        else:
            test = [preprocess(file.readlines()[int(index)])]
    return test


def log(ambs: Optional[Dict[int, REMultipattern]] = None):
    if ambs is None or len(ambs) == 0:
        print("No ambiguity found")
        return
    for k, v in ambs.items():
        print("Found: " + ("polynomial" if k == POLY_AMBIGUOUS else "exponential"))
        print("Pumping pattern:\n" + str(v))


def main(
    value: str,
    example: bool = False,
    radius: int = 10,
    timeout: float = 2,
    first: bool = False,
    pattern: bool = False,
    genetic: bool = False,
    rec_limit: int = 3,
    visualize: bool = False):

    matcher = RegexMatcher()
    analyzer = StaticAnalyzer()
    ambiguity_analyzer = AmbiguityAnalyzer()

    if pattern:
        fuzzer = REPatternFuzzer(
            GeneticFuzzer(), matcher, analyzer, ambiguity_analyzer)
    else:
        fuzzer = ERegexFuzzer(matcher, analyzer, ambiguity_analyzer)

    if len(example) > 0:
        for sample in test(value, example):
            print(f"Example: {sample}")
            sample = ERegexParser(sample).parse()
            try:
                if pattern:
                    log(fuzzer.run(
                        sample,
                        max_radius=radius,
                        timeout=timeout,
                        genetic=genetic,
                        rec_limit=rec_limit,
                        visualize=visualize,
                        first=first))
                else:
                    log(fuzzer.run(
                        sample,
                        max_radius=radius,
                        timeout=timeout,
                        rec_limit=rec_limit,
                        visualize=visualize,
                        first=first))
            except:
                log()
            print()
    else:
        sample = ERegexParser(value).parse()
        # try:
        if pattern:
            log(fuzzer.run(
                sample,
                max_radius=radius,
                timeout=timeout,
                genetic=genetic,
                rec_limit=rec_limit,
                visualize=visualize,
                first=first))
        else:
            log(fuzzer.run(
                sample,
                max_radius=radius,
                timeout=timeout,
                rec_limit=rec_limit,
                visualize=visualize,
                first=first))
        # except:
        #     log()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='''Dynamic complexity analysis of regular expressions and re-patterns''')
    parser.add_argument('value', help='value to analyze')
    parser.add_argument(
        '-e', '--example',
        action='store',
        default='',
        type=str,
        help='the path to the test file')
    parser.add_argument(
        '-v', '--visualize',
        action='store_true',
        help='whether to visualize pumping dependencies')
    parser.add_argument(
        '-t', '--timeout',
        action='store',
        default=2,
        type=float,
        help='the timeout for matching')
    parser.add_argument(
        '-r', '--radius',
        action='store',
        type=int,
        default=10,
        help='the max radius for neighborhood extension')
    parser.add_argument(
        '-p', '--pattern',
        action='store_true',
        help='re-pattern mode')
    parser.add_argument(
        '-g', '--genetic',
        action='store_true',
        help='whether to use genetic algorithms for analysis')
    parser.add_argument(
        '-d', '--depth',
        default=3,
        type=int,
        help='the limit for recursive opening of regexes')
    parser.add_argument(
        '-f', '--first',
        action='store_true',
        help='whether to show the first vulnerability')
    args = parser.parse_args()
    
    main(
        value=args.value,
        example=args.example,
        pattern=args.pattern,
        timeout=args.timeout,
        rec_limit=args.depth,
        genetic=args.genetic,
        radius=args.radius,
        first=args.first,
        visualize=args.visualize)

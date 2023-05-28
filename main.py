import argparse
from typing import Any, Optional

from src.const import *
from src.eregex.regex import *
from src.wrappers.static_analyzer import StaticAnalyzer
from src.multipattern.repattern import REPattern, REVariable
from src.dynamic_analyzer.pattern_fuzzer import REPatternFuzzer
from src.eregex.parser import ERegexParser
from src.wrappers.static_analyzer import StaticAnalyzer
from src.dynamic_analyzer.ambiguity_analyzer import AmbiguityAnalyzer
from src.wrappers.regex_matcher import RegexMatcher
from src.genetic.genetic_fuzzer import GeneticFuzzer


fuzzer = GeneticFuzzer()
matcher = RegexMatcher()
ambiguity_analyzer = AmbiguityAnalyzer()


def check_type_inside(source: Regex, type: Any) -> bool:
    if isinstance(source, type):
        return True
    if isinstance(source, ConcatenationRegex) or isinstance(source, AlternativeRegex):
        for value in source.value:
            if check_type_inside(value, type):
                return True
    return False


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

   
def fuzz(regex: Regex, analyzer: StaticAnalyzer, first: bool = True):
    pattern = regex_to_pattern(regex)
    regex = pattern.get_regex()
    if pattern is not None:
        refuzzer = REPatternFuzzer(fuzzer, matcher, ambiguity_analyzer)
        return refuzzer.run(pattern, first=first)
    return process(regex, analyzer)


def process(regex: Regex, analyzer: StaticAnalyzer, first: bool = True) -> int:
    if isinstance(regex, BaseRegex):
        return NO_AMBIGUOUS
    if isinstance(regex, StarRegex):
        status = process(regex.value, analyzer)
        if status > NO_AMBIGUOUS:
            return status
        if check_type_inside(regex.value, BackrefRegex):
            return NO_AMBIGUOUS
        else:
            return analyzer.analyze(str(regex))
    if isinstance(regex, AlternativeRegex):
        if not check_type_inside(regex, BackrefRegex):
            return analyzer.analyze(str(regex))
        else:
            for value in regex.value:
                status = process(value, analyzer)
                if status > NO_AMBIGUOUS:
                    return status
        return NO_AMBIGUOUS
    if isinstance(regex, ConcatenationRegex):
        if not check_type_inside(regex, BackrefRegex):
            return analyzer.analyze(str(regex))
        else:
            before = ""
            backrefs = []
            for value in regex.value:
                if not check_type_inside(value, BackrefRegex):
                    status = analyzer.analyze(before + str(value))
                    if status > NO_AMBIGUOUS:
                        return status
                    before += str(value)
                else:
                    backrefs.append(value)
            return fuzz(regex, analyzer)
    return NO_AMBIGUOUS


def main(regex_str: str, first: bool = True, plot: bool = True):
    analyzer = StaticAnalyzer()
    regex = ERegexParser(regex_str).parse()
    if plot:
        regex.plot().render(f"visualization/regex.gv", format="png").replace('\\', '/')
    parse(fuzz(regex, analyzer, first))


def parse(log: Any) -> str:
    if log == NO_AMBIGUOUS or len(log) == 0:
        print("No ambiguity found")
    else:
        for k, v in log.items():
            print(f"Found: {'polynomial' if k == POLY_AMBIGUOUS else 'exponential'}")
            print("Pumping pattern: " + "".join([f"{' '.join(r.shape())} = {r.get_regular_str()}" for r in v.value]))


if __name__ == "__main__":
    base_examples = ["a(a*)\\1))", "bcaa(c*)cccc\\1", "a(a*)(b|a)*a\\1"]

    parser = argparse.ArgumentParser(
        description='''Dynamic complexity analysis of regular expressions and re-patterns''')
    parser.add_argument('regex', help='regex to analyze')
    parser.add_argument(
        '-v', '--visualize',
        action='store',
        help='path to file for structure visualization')
    parser.add_argument(
        '-f', '--first',
        action='store_true',
        help='whether to show first vulnerability')
    
    args = parser.parse_args()
    main(args.regex, args.first, args.visualize)

    # module testing
    # parser = ERegexParser('(b*)\\1')
    # res = parser.parse()
    # res.plot().render(f"visualization/regex.gv", format="png").replace('\\', '/')
    # print([str(v) for v in res.value])

    # analyzer = StaticAnalyzer()
    # print(analyzer.analyze('(a*)*'))
    
    # matcher = RegexMatcher()
    # print(matcher.match_group([["a", "1"], "b"], {"1": [0, 30, 5]}, "a*a*"))

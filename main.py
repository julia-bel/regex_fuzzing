from src.eregex.parser import ERegexParser
from src.wrappers.static_analyzer import StaticAnalyzer
from src.wrappers.regex_matcher import RegexMatcher


if __name__ == "__main__":
    # module testing
    parser = ERegexParser('(b*)\\1')
    res = parser.parse()
    res.plot().render(f"visualization/regex.gv", format="png").replace('\\', '/')
    print([str(v) for v in res.value])

    analyzer = StaticAnalyzer()
    print(analyzer.analyze('(a*)*'))
    
    matcher = RegexMatcher()
    print(matcher.match_group([["a", "1"], "b"], {"1": [0, 30, 5]}, "a*a*"))

    
from src.eregex.parser import ERegexParser


if __name__ == "__main__":
    # basic example
    parser = ERegexParser('(b*)\\1')
    res = parser.parse()
    res.plot().render(f"visualization/regex.gv", format="png").replace('\\', '/')
    print([str(v) for v in res.value])
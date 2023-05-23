from src.eregex.parser import ERegexParser


if __name__ == "__main__":
    parser = ERegexParser('a*(b)*\1')
    res = parser.parse()
    res.plot().render(f"visualization/regex.gv", format="png").replace('\\', '/')
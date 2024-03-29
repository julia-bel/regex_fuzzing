from numpy import exp


END_MARKER = "-"
NO_AMBIGUOUS = 0
POLY_AMBIGUOUS = 1
EXP_AMBIGUOUS = 2
SUBSTITUTION = 0
CUTTION = 1
EPSILON = "ε"
EMPTY = ""
ALPHABET = set("abcdefghijklmnopqrstuvwxyz")

LINEAR_FUNC = lambda t, a, b: a * t + b
POLY_FUNC = lambda t, a, b: a * t**2 + b
EXP_FUNC = lambda t, a, b: a * exp(t) + b
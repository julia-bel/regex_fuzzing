from typing import Iterator


def key_generator() -> Iterator[str]:
    i = 0
    while True:
        yield str(i)
        i += 1

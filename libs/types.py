from dataclasses import dataclass
from typing import Protocol


@dataclass
class Result:
    n: int
    order: int | None = None

    def __hash__(self) -> int:
        return hash((self.n, self.order))


@dataclass
class ResultSet:
    n: set[int]
    order: int | None

    def __init__(self, n: int | set[int], order: int | None = None) -> None:
        if not isinstance(n, set):
            n = {n}
        self.n = n
        self.order = order

    def result_set(self) -> set[Result]:
        return {Result(n, self.order) for n in self.n}


class SupportsLog(Protocol):
    def log(self, base: "SupportsLog") -> int: ...

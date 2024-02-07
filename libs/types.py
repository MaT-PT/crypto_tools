from typing import Protocol


class SupportsLog(Protocol):
    def log(self, base: "SupportsLog") -> int: ...

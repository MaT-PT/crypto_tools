from argparse import Action, ArgumentError, ArgumentParser, ArgumentTypeError, Namespace
from typing import Any


class PointAction(Action):
    def __call__(
        self,
        parser: ArgumentParser,
        namespace: Namespace,
        values: Any,
        option_string: str | None = None,
    ) -> None:
        # print(f"{option_string}: {values} | {namespace}")
        if (option_string in ("-gx", "-gy") and namespace.G is not None) or (
            option_string == "-G" and not (namespace.gx is None and namespace.gy is None)
        ):
            raise ArgumentError(self, "generator point G already supplied")

        if (option_string in ("-px", "-py") and namespace.P is not None) or (
            option_string == "-P" and not (namespace.px is None and namespace.py is None)
        ):
            raise ArgumentError(self, "target point P already supplied")

        setattr(namespace, self.dest, values)


def my_int(value: str) -> int:
    try:
        if value.startswith("0x"):
            return int(value, 16)
        if value.startswith("0b"):
            return int(value, 2)
        if value.startswith("0o"):
            return int(value, 8)
        return int(value)
    except ValueError as e:
        raise ArgumentTypeError(str(e))

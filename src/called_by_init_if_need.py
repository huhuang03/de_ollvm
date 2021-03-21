from .function import Func

class CalledByInitIfNeed(Func):
    def __init__(self) -> None:
        super().__init__("CalledByInitIfNeed", 0x7ede0, 0x8004b)
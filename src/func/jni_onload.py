from ..function import Func
from ..llvm_function import LlvmFunction
import angr

class JniOnLoad(LlvmFunction):
    def __init__(self, p: angr.Project) -> None:
        super().__init__("JniOnLoad", 0x04518, 0x49ef, p)
import os.path as path
import angr
from elftools.elf.elffile import ELFFile
from .rubbish import RubbishType1, RubbishType2

SO_PATH = path.join(path.dirname(path.abspath(__file__)), "ollvm_demo.so")
print(SO_PATH)

# push R0-R3
# mov r0, pc
# mov r1, pc
# R_PUSH_START_1 = b'x0fxb4x78x46x79x46'
R_PUSH_START_1 = b'\x0f\xb4'

# pop r0-r3
R_PUSH_END_1 = b'\x0f\xbc'

# push R0-R3, r7
# mov r0, pc
# mov r1, pc
R_PUSH_START_2 = b'x8fxb4x78x46x79x46'

# pop r7
# pop r0-r3
R_PUSH_START_2 = b'x07xbcx88xbc'

class SoFile:
    global SO_PATH
    def __init__(self) -> None:
        self.p = angr.Project(SO_PATH)
        f = open(SO_PATH, 'rb')
        self.content = f.read()
        self.elf = ELFFile(f)
        self.text = self.elf.get_section_by_name(".text")
        self.text_start = self.text['sh_offset']
        self.text_end = self.text_start + self.text.header['sh_size']


cms: SoFile = SoFile()
rubbish1 = RubbishType1()
rubbish2 = RubbishType2()
import os
import os.path as path
import barf
from .func import Func

# This is the function be called by many place
# This function do the logic(decompress, deny check and so on)
init_if_need = Func('init_if_need', 0x8004c)


# This magic jump is very intreasting.
magic_jump = Func('magic_jump', 0x23b4)

SO_PATH = path.join(path.dirname(path.abspath(__file__)), "ollvm_demo.so")

INIT_0_START = 0x754c

if not path.exists(SO_PATH):
    exit("N")

so_barf = barf.BARF(SO_PATH)

# print(so_barf)
for addr, asm_instr, reil_instrs in so_barf.translate(INIT_0_START):
    print("0x{addr:08x} {instr}".format(addr=addr, instr=asm_instr))
    for reil_instr in reil_instrs:
        print("{indent:11s} {instr}".format(indent="", instr=reil_instr))
# cfg = so_barf.recover_cfg()
# cfg.save("branch1_cfg")
from . import util

class JumpTable:
    def __init__(self, addr, ex_node) -> None:
        self.addr = addr
        self.ex_node = ex_node


class ExNode:
    def __init__(self, p, node) -> None:
        self.p = p
        self.node = node
        self.jump_table = []
        self.insts = self.p.factory.block(node.addr).capstone.insns
        self.jumps = []
        self.successors = set()
        self.cfg_nodes = node.cfg_nodes
        self.addr = node.addr

        for n in self.insts:
            if n.mnemonic.startswith('b'):
                self.jumps.append(self.insts.index(n))

    def is_last_jump(self) -> bool:
        return self.insts[len(self.insts) - 1].mnemonic.startswith('b')

    def is_mystery(self) -> bool:
        has_nop = False
        has_add_sp = False
        has_sub_sp = False

        for n in self.insts:
            if util.insn_is_starts_with(n, 'add sp'):
                has_add_sp = True
            if util.insn_is_starts_with(n, 'nop'):
                has_nop = True
            if util.insn_is_starts_with(n, 'sub sp'):
                has_sub_sp = True
        return has_nop and has_add_sp and not has_sub_sp


    def __eq__(self, o: object) -> bool:
        return isinstance(0, ExNode) and self.node == o.node

def insn_is_starts_with(insn, order):
    return (insn.mnemonic + " " + insn.op_str).startswith(order)


def insns_any_startsw_with(insns, order):
    for n in insns:
        if insn_is_starts_with(n, order):
            return True
    return False

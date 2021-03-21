def get_reg_as_str(s, reg):
    pointer = s.solver.eval(reg)
    s_bv = s.memory.load(pointer, 10)
    s_bytes = s.solver.eval(s_bv, cast_to=bytes)
    return s_bytes
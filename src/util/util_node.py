def node_print_insns(p, n):
    insns = p.factory.block(n.addr).capstone.insns
    for insn in insns:
        print(str(insn))


def nodes_get_node_at(nodes, addr):
    for n in nodes:
        for cfg_node in n.cfg_nodes:
            # print(hex(cfg_node.addr))
            if cfg_node.addr == addr:
                return n
    return None
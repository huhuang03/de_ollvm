from typing import List


class NodeTreeNode:
    def __init__(self, node, parent = None, children: List = []) -> None:
        self.node = node
        self.parent = parent
        self.children = children
    
    def add_child(self, node):
        tree_ndoe = NodeTreeNode(node, self, [])
        self.children.append(tree_ndoe)
        return tree_ndoe

    def dump(self, leveL: int = 3):
        index = 0
        nodes = [self]
        while index < leveL:
            children = []
            print([n.node for n in nodes])
            for n in nodes:
                children.extend(n.children)
            nodes = children

            index += 1

    def _dump1_print_node(self, node, level):
        text = ''
        prefix = '├── '
        if node:
            text += ' ' * len(prefix) * (level - 1)
            if level > 0:
                text += prefix
            print(f'{text}{hex(node.node.addr)}')

    def _dump1_node(self, node, level, limit: int):
        if limit > 0 and node:
            self._dump1_print_node(node, level)
            for n in node.children:
                self._dump1_node(n, level + 1, limit - 1)

    def dump1(self, limit: int = 10):
        self._dump1_node(self, 0, limit)

    def flat_child(self, child):
        self.children.remove(child)
        self.children.extend(child.children)
        for c in child.children:
            c.parent = self

    # def show():
    #     pass

    # def _travel():
    #     pass

    # def remove_child(self, child):
    #     self.children.remove(child)
        
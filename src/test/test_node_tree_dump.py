from ..node_tree import NodeTreeNode

class Node:
    def __init__(self, addr) -> None:
        self.addr = addr
    

def main():
    root = NodeTreeNode(Node(0))
    root1 = root.add_child(Node(1))
    root1.add_child(Node(3))
    root2 = root.add_child(Node(2))
    root2.add_child(Node(4))
    root.dump1()


if __name__ == "__main__":
    main()
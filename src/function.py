class Func:
    def __init__(self, name, start, end) -> None:
        print("Func called")
        self.name = name
        self.start = start
        self.end = end

    def creat_init_state(self, p):
        return p.factory.blank_state(addr=self.start+1)
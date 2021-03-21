import angr

class Project():
    def __init__(self, wrapper: angr.Project) -> None:
        self.p: angr.Project = wrapper

    def step_till_call_or_two_state(self, init_state):
        sm = self.p.factory.simulation_manager(init_state)
        pre = None
        while len(sm.active) < 2:
            sm.step()
            print(sm)

            if len(sm.active) < 2:
                print(sm.active)
                # pre = sm.active
            # print(sm.active)
        print(sm.active)
        print(pre)

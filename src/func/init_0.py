from src.util.util_reg import get_reg_as_str
from ..llvm_function import LlvmFunction
import angr

class print_hook(angr.SimProcedure):
    def run(self, str, end, base):
        print('openat called')
        exit()
        state = self.state
        # r0: <SAO <BV32 0x22b>>, r1: <SAO <BV32 0xffffff9c>>, r2: <SAO <BV32 0x7ffeff56>>, r3: <SAO <BV32 0x0>>
        # sp: <0x7ffefd98>
        # fd = 0xffffff9c
        # path = 0x7ffeff56 strange. it's stack??
        print(f'r0: {state.regs.r0}, r1: {state.regs.r1}, r2: {state.regs.r2}, r3: {state.regs.r3}, sp: {state.regs.sp}')
        pointer = state.solver.eval(state.regs.r2)
        s_bv = state.memory.load(pointer, 10)
        s_bytes = state.solver.eval(s_bv, cast_to=bytes)
        # look like all zero??
        print(s_bytes)
        # can I swith to ipython??
        # how to output the state??
        # print('pring hook called')
        # pass
        # return self.state.solver.BVS("flag", 64, explicit_name=True)

class hook_first_call_init_if_need(angr.SimProcedure):
    def run(self, str, end, base):
        s = self.state
        print('hook_first_call_init_if_need')
        print(f'r0: {s.regs.r0}, r1: {s.regs.r1}, r2: {s.regs.r2}, r3: {s.regs.r3}')
        print(f'r4: {s.regs.r4}, str(r4): {get_reg_as_str(s, s.regs.r4)}, sp: {s.regs.sp}')
        # print(f'path: {s.regs.r2}')
        exit()

class Init0(LlvmFunction):
    def __init__(self, p: angr.Project) -> None:
        super().__init__("init_0", 0x754c, 0x884f, p)

    def debug_execute(self):
        self.p.hook(0x7f5e, print_hook())
        self.p.hook(0x7f4a, hook_first_call_init_if_need())

        def set_callless_to_state(s) -> bool: 
            s.options.add(angr.sim_options.CALLLESS)
            return True

        start_s = self.p.factory.blank_state(addr=self.start + 1, option=[angr.sim_options.CALLLESS])
        sm: angr.SimulationManager = self.p.factory.simulation_manager(start_s)
        while True:
            sm.step(selector_func=set_callless_to_state)
            # print(f'{sm.active}')
            # print(f'{sm.active} pc: {sm.one_active.regs.pc}')
            if len(sm.active) <= 0:
                break
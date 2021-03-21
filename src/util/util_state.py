def state_step_util_two_state(state):
    step_rst = state.step()
    while len(step_rst.all_successors) == 1:
        step_rst = step_rst.all_successors[0].step()
    return step_rst
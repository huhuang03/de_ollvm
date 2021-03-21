from .func import Func

# This magic jump is verty intresting.

# So we will anylysis this.

# The strange code is:

# pus {r7, lr}

# add r7, sp, #0
# sub sp, #0x28
# mov r2, r1
# mov r3, r0
# str r0, [sp, #local_18]
# str r2, [sp, #local_28]
# mov r0, r7
# str r0, [sp, #local_1c]
# lsr r0, r0, #0xc ; sp >> 0xc
# cmp r0, #0

# if != 0 {
    # mov r0, #0
    # str r0, [sp, #local_c]
# } else {
    # what's this fuck?
    # ldr r0, [sp, #local_1c]
    # ldr r0, [r0, #0]
    # str r0, [sp, #local_20]
    # ldr r0, [sp, #local_1c]
    # ldr r0, [r0, #0x4]
    # str r0, [sp, #local_24]
    # ldr r0, [sp, #local_1c]
    # mov r1, #0
    # str r1, [r0, #0]
    # ldr r1, [sp, #local_18]
    # ldr r2, [sp, #local_1c]
    # str r0, [r2, #4]
    # ldr r2, [sp, #local_24]
    # add r2, #0xd5
    # ldr r1, [sp, #local_20]
    # add r1, #0xe9
    # ldr r0, [sp, #local_c]
# }
# add sp, #0x28
# pop {r7, pc}

# So, where is the magic??


# and now I will try to translate the logic
# push {r7, lr}
# r7 = old_sp
# local_18 = call_addr
# local_28 = p_params

# local_1c = old_sp
# local_20 = origin_r7

# local_24 = lr

# r0 = old_sp
# r1 = 0
# [old_sp] = 0

# sp_lr = call_addr
# r2 = lr + 5
# r1 = origin_r7 + 0xe9
# r0 = p_params
# r7 = 0
# call call_addr


# so what's magic real do.
def MagicJumpFunc(Func):
    pass

    # the call monitor
    def monitor_call(p1, p2, p3):
        """
        p1 pass by r0
        p2 pass by r1
        p3 pass by r7
        """
        # var lr
        r0 = p2
        r1 = p3 + 0xe9

        r2 = lr + 5
        lr = p1
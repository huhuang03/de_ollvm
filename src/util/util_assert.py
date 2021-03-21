def assert_msg(check, msg):
    if not check:
        raise AssertionError(msg)
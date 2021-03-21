def mnemonic_is_jump(mnemonic: str):
    if not mnemonic.startswith('b'):
        return False
    if mnemonic.startswith('bl'):
        if mnemonic.startswith('ble') and not mnemonic.startswith('bleq'):
            return True
        else: return False
    return True

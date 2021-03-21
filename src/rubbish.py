import os
from os.path import curdir
from keystone import *

ks = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
nop_encoding, nop_count = ks.asm("nop")

class Rubbish:
    global nop_encoding
    global nop_count

    def __init__(self, start_feature, end_feature, fixed_size) -> None:
        self.start_feature = start_feature
        self.end_feature = end_feature
        self.fixed_size = fixed_size
        self.map_str = ""

    # r1 0x234e - 0x23a4
    def patch(self, content, start_i, end_i):
        jump_end = end_i + len(self.end_feature)
        jump = f"b #{jump_end - start_i}"
        jump_encoding, count = ks.asm(jump)

        content[start_i: start_i + len(jump_encoding)] = jump_encoding

        nop_start = start_i + len(jump_encoding)
        nop_end = jump_end - len(nop_encoding)

        # 这里+1是以为range为），而我们想要的是]
        for i in range(nop_start, nop_end + 1, len(nop_encoding)):
            content[i: i + len(nop_encoding)] = nop_encoding


    def process(self, content, start_i, end_i)->bytearray:
        print(type(content))
        rst_content = bytearray(content)
        self.map_str = ""
        while start_i < end_i:
            rub_begin_1 = content.find(self.start_feature, start_i)
            if rub_begin_1 % 2 != 0:
                start_i += 1
                continue

            if rub_begin_1 != -1:
                print(f"find: {hex(rub_begin_1)}")
                start_i = rub_begin_1 + 2

                rub_end_1 = content.find(self.end_feature, start_i)
                print(f"len: {rub_end_1 - rub_begin_1}")
                assert(rub_end_1 - rub_begin_1 == self.fixed_size)
                self.map_str += f"{hex(rub_begin_1)} - {hex(rub_end_1)}\n"
                self.patch(rst_content, rub_begin_1, rub_end_1)
            else:
                print("find end")
                break
        return rst_content

    def write(self, out_folder):
        map_file_path = os.path.join(out_folder, self.get_prefix() + "_maps.txt")
        # print(self.map_str)
        open(map_file_path, "w").write(self.map_str)

    def get_prefix(self):
        return "unk"


class RubbishType1(Rubbish):
    def __init__(self) -> None:
        Rubbish.__init__(self, b'\x0f\xb4\x78\x46\x79\x46', b'\x0f\xbc', 86)

    def get_prefix(self):
        return 'rubbish_1'

class RubbishType2(Rubbish):
    def __init__(self) -> None:
        Rubbish.__init__(self, b'\x8f\xb4\x78\x46\x79\x46', b'\x07\xbc\x88\xbc', 84)

    def get_prefix(self):
        return 'rubbish_2'
import sys
from struct import *

sys.path.append("..")
from qiling import *
from qiling.const import QL_VERBOSE
from unicorn.unicorn_const import UC_MEM_WRITE
from unicorn.unicorn_const import UC_MEM_READ

def myhook(ql: Qiling) -> None:
  print('asked for '+str(ql.arch.regs.rdi)+' bits of random')

def canary_gen(ql: Qiling) -> None:
  print('canary generated = '+hex(ql.arch.regs.rdi))

def myhook_ret(ql: Qiling) -> None:
  print('LFSR returned: '+hex(ql.arch.regs.rax))

def getrandom(ql: Qiling) -> None:
  buff = ql.unpack64(ql.mem.read(ql.arch.regs.rdi, 8))
  print('syscall getrandom returned: '+hex(buff))

def my_sandbox(path, rootfs):
    ql = Qiling(path, rootfs, verbose=QL_VERBOSE.OFF)
    ql.hook_address(myhook, 0x40146c)
    ql.hook_address(myhook_ret, 0x4014ad)
    ql.hook_address(canary_gen, 0x401064)
    ql.hook_address(getrandom, 0x401296)
    ql.run()

if __name__ == "__main__":
    my_sandbox(["./examples/rootfs/x8664_linux/bin/loader"], "./examples/rootfs/x8664_linux")

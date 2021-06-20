import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

buff = b''
def xor_func(ql):
  global buff
  if (ql.reg.ecx):
    buff += ql.reg.ecx.to_bytes(4,'little')
    print('FLAG: '+buff.decode('UTF-8'))

if __name__ == "__main__":
    ql = Qiling(["./crapsemu"], "rootfs/x8664_linux", verbose=QL_VERBOSE.OFF, stdin="pipo")
    ql.hook_address(xor_func, 0x555555555cbe)
    ql.run()

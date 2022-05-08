import os
import sys
import tempfile
import subprocess
from capstone import *

def isInvalid(ins):
	forbidden = [CS_GRP_JUMP, CS_GRP_CALL, CS_GRP_RET, CS_GRP_INT,
		CS_GRP_IRET] # CS_GRP_BRANCH_RELATIVE only exists in C
	return any(filter(lambda group: group in forbidden, ins.groups))

def check(SC):
	md = Cs(CS_ARCH_X86, CS_MODE_64)
	md.detail = True
	ok = True
	for i in md.disasm(SC, 0):
		ok &= not isInvalid(i)
	return ok and (SC == SC[::-1])

def run(SC):
	tmp = tempfile.mkdtemp(dir = "/dev/shm/", prefix = bytes.hex(os.urandom(8)))
	fn = os.path.join(tmp, "shellcode")
	with open(fn, "wb") as f:
	    f.write(SC)

	try:
		subprocess.run(["./execut0r", fn], stderr = sys.stdout, timeout = 120)
	except:
		pass

	os.remove(fn)
	os.rmdir(tmp)

if __name__ == "__main__":

	print("Enter your shellcode (hex, at most 1024 bytes):")
	try:
		SC = bytes.fromhex(input())

		assert len(SC) <= 1024
		assert check(SC)

		prolog = bytes.fromhex("4831C04831DB4831C94831D24831FF4831F64D31C04D31C94D31D24D31DB4D31E44D31ED4D31F64D31FF4831ED")
		epilog = bytes.fromhex("0f05")
		run(prolog + SC + epilog)
	except:
		print("Please check your input.")
		exit(1)

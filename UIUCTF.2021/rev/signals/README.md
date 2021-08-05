This reverse was an easy one,

it is a binary, that ask for the flag as is only argument.

it does a mprotect , to change it's data section mapping to RWX,

and execute a code in this RWX part (self modifying code indeed)

the code is a bloc like this

![](https://imgur.com/uvajKkR.png)

it loads the next bloc address to be decoded in RAX,

then xor it with the corresponding char of the input flag (from first to last)

each bloc is the same sizeof 0x1d,  and contains the same instructions bloc..

as we know the beginning of the flag "uiuctf{",

we can decode the first bloc easily..

to verify that they are all the same..

and as we know the value of the opcodes in the next bloc, we can deduce the next char in flag,

by xoring a known value opcode by it's xored value..

to resolve this, I write a python GDB script with pwntools that dumps the flag automatically

just set the terminal you will use in context.terminal line.. (gdb script use gef also, set the right path to gef)

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import os

context.update(arch="amd64", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=-2', '--geometry=128x98+1100+0', '-e']
context.log_level = 'error'

exe = ELF('./signals')
print('decoding you flag with gdb script, wait a bit...')
os.system('rm flag.txt')

script = '''
source ~/gdb.plugins/gef/gef.py
tbreak main
set follow-fork-mode child
set detach-on-fork off
c
pie breakpoint *0x4020
c
'''
for i in range(39):
  script += '''
    stepi 2
    set $dl = (*(unsigned char *)($rax+0x1b) ^ 0xff)
    dump value out.bin $dl
    shell cat out.bin >> flag.txt
    hb *$rax
    c
    delete
    '''

script += '''
  stepi 2
  set $dl = (*(unsigned char *)($rax+0x1b) ^ 0xff)
  p $dl
  q
  '''

p = gdb.debug([exe.path, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'], gdbscript = script)

try:
  p.recv()
except:
  print('your flag:')

os.system('cat flag.txt;echo }')
```

*nobodyisnobody still reversing things..*

see it in action :)

![](https://imgur.com/8v3ISGM.gif)

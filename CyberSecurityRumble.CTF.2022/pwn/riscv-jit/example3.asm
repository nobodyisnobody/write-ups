li a0,0x2f148800
li a1,0xffff
sw a0,0(a1)

li a0,0xfff8
lw a1,0(a0)
li a2,0xff
beq a1,a2,next
sb a2,0(a0)
li ra,0x8a
ret

next:
li a0,0xfff0
li a1,0x200
li a7,1
ecall
li ra,0x8a
ret

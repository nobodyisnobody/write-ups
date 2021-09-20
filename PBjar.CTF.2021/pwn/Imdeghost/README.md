**Imdeghost**,

was a pwn challenge from PB.Jar.CTF.2021,  also written by Rythm.

It has only 3 solves and was a bit hard.

let's check the program permission first

![](https://github.com/nobodyisnobody/write-ups/raw/main/PBjar.CTF.2021/pwn/Imdeghost/pics/checksec.png)

ok , lets reverse the program, almost all is in the main function.

![](https://github.com/nobodyisnobody/write-ups/raw/main/PBjar.CTF.2021/pwn/Imdeghost/pics/reverse.png)

well basically the program allocate two memory zone:

* One at 0x0000006900000000 that will be used as a Stack. (RW- only)
* One at 0x0000133700000000 that will contains executable program. (--X only)

the exec zone, is first marked write only, and the program copy a program prelude to it, that will be executed before our code.

then it change the exec zone protection, to be exec only, so no more readable or writable...

the prelude code looks like this..

![](https://github.com/nobodyisnobody/write-ups/raw/main/PBjar.CTF.2021/pwn/Imdeghost/pics/prelude.png)

basically it clears all registers, and set RSP register to the stack at 0x0000006900000000, then it close stdin, stdout, and stderr..

so we cannot leak or read anything...

when the prelude returns, it will take it return address from first address of stack at 0x0000006900000000, so we can put a ROP to it..

but it's not an easy task, as we have no idea, where the program or libc is mapped..all the registers are cleared..

all we know is the address of stack & exec zone..that's all

well in fact we have something, look at this line in the reverse..

> v5 = (unsigned __int8)read(0, stk, 0x1000uLL);

the var v5 on stack, will contains lsb byte (unsigned int8) of number of byte read from our input..

then when the prelude is called in exec zone, it is passed as an argument to it

> ((void (__fastcall *)(_QWORD))exe)(v5);

at the beginning of the prelude , this value in rdi (1st arg), is stored in r15, and restore back to us in rax, before the return to our ROP

so basically we can control rax value, with the lsb byte value of the total bytes we send as input..

for exemple , if we send 0x40f bytes,  we will have rax = 0x0f

if we send 0x413 bytes, we will have rax = 0x13....and so on....

last thing important , the security() function setup a seccomp sandbox to forbid some syscall before calling the prelude...

![](https://github.com/nobodyisnobody/write-ups/raw/main/PBjar.CTF.2021/pwn/Imdeghost/pics/seccomp.png)

the system calls; mmap, mprotect, execve, remap_file_pages, execveat, and pkey_mprotect are forbidden so...

so what can we do???

well we control rax, and have plenty of space (up to 0x1000 byte) on stack to ROP and store data...

the answer is SIGROP..

I will not explain sigrop in details, you can find many tutorials on it on google..

but to be quick, when you call the system call sigreturn, it will restore all the registers from a stack frame that is stored at current address on stack,

as if we were returning from a signal handler..

What is good is that sigreturn, needs no argument, so we can call it by setting rax = 15 , that is sigreturn syscall number in 64bit..

then we can do successive sigrop, as a sigrop chain.  Each sigrop will setup the next RSP value, and set up rax,rdi,rsi,rdx, to the right values..

the rip value will point to the only usefull gadget for us..

> gadget0 = 0x000013370000004b # syscall

which is the last part of the prelude code, that we will use as a syscall gadget. This one is at a fixed and known address, so it's enough for the sigrop..

as we have no stdin , stdout, stderr opened..

we will do a connect back ROP with our sigrop, that connect back to a box we control.

we will do the exploitation in two times..

first, a ROP that connect back to us, and do a getdents to have directory contents value, and send its raw data result over the socket..

like this we will know the name of the flag file to open, as it is unknown to us...

second, a ROP that connect back to us, open the filename of the flag, and send us back the flag content over the socket..

so you just need to setup a listener:   nc -l -p PORT on a box you control (make sure the port is reachable from outside, from the internet)

and execute the two exploits...

the result looks like this

![](https://github.com/nobodyisnobody/write-ups/raw/main/PBjar.CTF.2021/pwn/Imdeghost/pics/gotshell.png)

the two exploits are on my github.

*nobodyisnobody still pwning things*


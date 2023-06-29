## write-flag-where 1 , 2, and 3

 were a serie of 3 challenges from Google CTF Quals 2023.

not really difficult, just tricky

basically the programs give us the memory mapping address by dumping `/proc/self/maps`

then you can write the number of characters you want from the flag, where you want in memory.

The program use `/proc/self/mem`for doing that,  you can write over read-only zones too..

well so here are the solutions:

------

#### 1st - write-flag-where: 

for the first one you can just write the flag over the string at offset 0x21e0 "Give me and address and a length...",  and it will be dumped next round.

#### 2nd - write-flag-where2:

this time the `dprintf` message output was removed from the main loop, but by inspecting the code after the `exit` part,  you can see that there is a `dprintf` code given by the challenge author that is not reachable.

```assembly
.text:000000000000143B                                  loc_143B:                               ; CODE XREF: main+24F↑j
.text:000000000000143B BF 00 00 00 00                                   mov     edi, 0          ; status
.text:0000000000001440 E8 8B FC FF FF                                   call    _exit
.text:0000000000001445                                  ; -----------------------------------------------
.text:0000000000001445 8B 45 F4                                         mov     eax, [rbp+var_C]
.text:0000000000001448 48 8D 15 86 0C 00 00                             lea     rdx, large cs:20D5h ; "Somehow you got here??\n"
.text:000000000000144F 48 89 D6                                         mov     rsi, rdx        ; fmt
.text:0000000000001452 89 C7                                            mov     edi, eax        ; fd
.text:0000000000001454 B8 00 00 00 00                                   mov     eax, 0
.text:0000000000001459 E8 32 FC FF FF                                   call    _dprintf
.text:000000000000145E E8 CD FB FF FF                                   call    _abort

```

so the idea, is to write the flag over the *"Somehow you got here??\n"* string at offset **0x20d5** with the flag.

then to overwrite the `call _exit`opcodes at offset 0x1440 to 0x1444, with the flag..to nop it..

we know the flag start by "CTF{",  or `4354467B` in hexadecimal.

```sh
pwn disasm -c amd64 '4354'
   0:    43 54                    rex.XB push r12
```

```sh
pwn disasm -c amd64 '54'
   0:    54                       push   rsp
```

like you see , by using part of the flag, you can generate `push` instruction, that we will use to `nop` the `call _exit`

so once `call _exit` is erased ,when we will exit the flag will be dumped

I think that's the intended solution, one of my teammate used a more original solution,

you can use `sscanf` as an oracle, by overwriting the the first char of **"0x%llc %u"** with a character from the flag,

and leak it char by char.

#### 3rd - write-flag-where3:

this time the program forbids you to write in the zone `main-0x5000` to `main+0x5000`,  so you can not modify the program anymore..

The solution we found was to overwrite libc `open64` function prelude, and replace `sub rsp, 0x68`  by `sub rsp, 0x43` by writing the first char of the flag upon the `sub` instruction opcodes.

That will permit us to pivot on the `read()` buffer on stack at the time of exiting `open64()`, in the stack buffer we can put a small rop, a gadget to align stack, and a jump to a onegadget..

and that's all..


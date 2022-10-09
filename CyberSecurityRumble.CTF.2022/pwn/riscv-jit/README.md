Quick explanation for riscv-jit..



we use recursion of bson opcode 6 to overwrite an entry in the riscv jump table at address 0x3e4

we replace entry for opcode 5 with a jump to read function()

with the read function we read another riscv shellcode and jump to it

this second shellcode read a third shellcode at address 0x86

this third shellcode use overflow of rw zone to rwx zone by writing a dword at address 0xffff,

3 bytes will overflow in the rwx zone..

we use this overflow to overwrite a rwx chunk_map , with a single `mov [rdi+rbp],dl`

that will expand mem  size in vm_state ,

then we read a x86 shellcode in the rwx zone and jumps to it...

and that's all...


Various Write-ups from various CTFs..

as a Pwner for various team (Water Paddler, RootMeUpBeforeYouGoGo, etc...)

or alone to practice..(Team --> Armitage)


**Chaos, at a higher level, some see order in it...**

Let's try, to find order in chaos...

---

<details>
  <summary><strong>Heap Challenges</strong></summary>

  ### libc 2.35

  - **0CTF TCTF 2022** --> babyheap
    * [https://github.com/nobodyisnobody/write-ups/tree/main/0CTF.TCTF.2022/pwn/babyheap]()
    * *seccomp in place, heap overflow due to type confusion,  do chunk overlap for leak, then two tcache poisonning attacks*
    * *code execution via forging dtor_list table in tls-storage, and erasing the random value at fs:0x30*

  ### libc 2.34

  - **MetaCTF 2021** --> hookless
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/Hookless]()
    * *double free in delete function,uaf in edit function (usable once),uaf in display() function too*
    * *House of Botcake attack, we overwrite IO_2_1_stdout with environ address to leak stack address*
    * *we write a ROP directly on stack to achieve code execution*

  ### libc 2.32

  - **vsCTF 2022** --> EZorange
    * [https://github.com/nobodyisnobody/write-ups/tree/main/vsCTF.2022/pwn/ezorange]()
    * *oob read/write in edit function, no free available, use same method than house of orange to free chunks*
    * *we free two chunks, then do tcache poisonning with the oob, and overwrite __malloc_hook*

  ### libc 2.31
  - **justCTF 2022*** --> notes
    * [https://github.com/nobodyisnobody/write-ups/tree/main/justCTF.2022/pwn/notes]()
    * *fastbin dup attack, then write to __free_hook*

  - **idek CTF 2021** --> stacknotes
    * [https://github.com/nobodyisnobody/write-ups/tree/main/idekCTF.2021/pwn/stacknotes]()
    * *malloca alloc chunk on stack depending on size,we forge a fake chunk on stack, do a house of spirit attack on it*
    * *then alloc a chunk on stack with our ROP that overwrite return address*

  - **Tamil CTF 2021*** --> University
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Tamil.CTF.2021/pwn/University.Pwn]()
    * *overflow in edit because of strlen on a non-zero terminated string, will give us a read/write primitive*
    * *we set tcache.count in tcache_perthread_struct to 7 , to make a chunk goes to unsorted, to have a libc address leak*
    * *we edit tcache_entry of bloc of size 0x20 to __free_hook*

  ### libc 2.27
  - **RaR CTF 2021** --> unintended
    * [https://github.com/nobodyisnobody/write-ups/tree/main/RaRCTF.2021/pwn/unintended]()
    * *heap overflow because of strlen usage, then make overlapping chunk & tcache poisonning*
    * *finally overwrite __free_hook*
 
  ### libc 2.25
  - **Tamil CTF 2021*** --> Vuln Storage
    * [https://github.com/nobodyisnobody/write-ups/blob/main/Tamil.CTF.2021/pwn/Vuln.Storage/]()


</details>

<details>
  <summary><strong>Code execution after exit</strong></summary>

  - **Imaginary CTF 2022** --> rope
    * [https://github.com/nobodyisnobody/write-ups/tree/main/imaginary.CTF.2022/pwn/rope]()
    * *code execution via overwriting _rtld_global+3848 , that is __rtld_lock_lock_recursive (GL(dl_load_lock));*
    * *and pivoting in _rtld_gloval , via gets() and setcontext gadget* 

</details>

<details>
  <summary><strong>Kernel exploitation challenges</strong></summary>

  - **UTCTF 2022** --> bloat
    * [https://github.com/nobodyisnobody/write-ups/tree/main/UTCTF.2022/pwn/bloat]()
    * *use write primitive in kernel module, to overwrite modprobe_path*

</details>

</details>

<details>
  <summary><strong>SIGROP challenges</strong></summary>

  - **Tamil CTF 2021** --> Insecure system
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Tamil.CTF.2021/pwn/Insecure.System]()
    * *ROP & sigrop*

  - **Tamil CTF 2021** --> Stress Rope
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Tamil.CTF.2021/pwn/Stress.Rope]()
    * * small echo server in assembly, very few gadgets --> ROP & sigrop*

  - **PBjar CTF 2021** --> Imdeghost
    * [https://github.com/nobodyisnobody/write-ups/tree/main/PBjar.CTF.2021/pwn/Imdeghost]()
    * *restricted shellcode, resolved via connect back shellcode done in sigrop*
    
</details>

<details>
  <summary><strong>FSOP challenges</strong></summary>

  - **SECCON CTF 2022 Quals** --> Baby file
    * [https://github.com/nobodyisnobody/write-ups/blob/main/SECCON.CTF.2022.Quals/pwn/babyfile/]()
    * *libc-2.31 based fsop exploitation, _wide_data is NULL and non reachable, we populate pointers first*
    * *then leak libc & random value at fs:0x30, we forge onegagdet mangled address and have code execution via _cookie_write*

</details>

<details>
  <summary><strong>restricted shellcode challenges</strong></summary>

  - **Redpwn CTF 2021** --> gelcode-2
    * [https://github.com/nobodyisnobody/write-ups/tree/main/RedpwnCTF.2021/pwn/gelcode-2]()
    * *shellcode with only opcodes from 0 to 5, and a seccomp that force open/read/write shellcode*

  - **MetaCTF 2021** --> sequential shellcode
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/Sequential.Shellcode]()
    * *shellcode where every byte must be bigger then the preceding one*

</details>

<details>
  <summary><strong>Format string challenges</strong></summary>

  - **PBjar CTF 2021** --> wallstreet32
    * [https://github.com/nobodyisnobody/write-ups/tree/main/PBjar.CTF.2021/pwn/Wallstreet32]()
    * *restricted format string with many format chars forbidden, use trick '%*\n' to get a leak (libc-2.31 based)*

</details>

<details>
  <summary><strong>Various ROP challenges</strong></summary>

  - **MetaCTF 2021** --> An Attempt Was Made
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/A.Attempt.Was.Made]()
    * *restricted rop, execve forbidden, few gadgets (no libcsu_init gadget), use only add_gadget to forge gadgets*

</details>



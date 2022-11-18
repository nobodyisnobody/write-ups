Various Write-ups from various CTFs..

as a Pwner for various team (Water Paddler, RootMeUpBeforeYouGoGo, etc...)

or alone to practice..(Team --> Armitage)


**Chaos, at a higher level, some see order in it...**

Let's try, to find order in chaos...

<details>
  <summary><strong>Heap Challenges</strong></summary>

  ### libc 2.35

  - **0CTF TCTF 2022** --> babyheap
    * [https://github.com/nobodyisnobody/write-ups/tree/main/0CTF.TCTF.2022/pwn/babyheap]()
    * *seccomp in place, heap overflow due to type confusion,  do chunk overlap for leak, then two tcache poisonning attacks*
    * *code execution via forging dtor_list table in tls-storage, and erasing the random value at fs:0x30*

  ### libc 2.31
  - **justCTF 2022*** --> notes
    * [https://github.com/nobodyisnobody/write-ups/tree/main/justCTF.2022/pwn/notes]()
    * *fastbin dup attack, then write to __free_hook*

  - **idek CTF 2021** --> stacknotes
    * [https://github.com/nobodyisnobody/write-ups/tree/main/idekCTF.2021/pwn/stacknotes]()
    * *malloca alloc chunk on stack depending on size,we forge a fake chunk on stack, do a house of spirit attack on it*
    * *then alloc a chunk on stack with our ROP that overwrite return address*

  ### libc 2.32

  - **vsCTF 2022** --> EZorange
    * [https://github.com/nobodyisnobody/write-ups/tree/main/vsCTF.2022/pwn/ezorange]()
    * *oob read/write in edit function, no free available, use same method than house of orange to free chunks*
    * *we free two chunks, then do tcache poisonning with the oob, and overwrite __malloc_hook*

</details>

<details>
  <summary><strong>Code execution after exit</strong></summary>

  - **Imaginary CTF 2022** --> rope
    * [https://github.com/nobodyisnobody/write-ups/tree/main/imaginary.CTF.2022/pwn/rope]()
    * *code execution via overwriting _rtld_global+3848 , that is __rtld_lock_lock_recursive (GL(dl_load_lock));*
    * *and pivoting in _rtld_gloval , via gets() and setcontext gadget* 

</details>

<details>
  <summary><strong>Kernel exploitation</strong></summary>

  - **UTCTF 2022** --> bloat
    * [https://github.com/nobodyisnobody/write-ups/tree/main/UTCTF.2022/pwn/bloat]()
    * *use write primitive in kernel module, to overwrite modprobe_path*

</details>

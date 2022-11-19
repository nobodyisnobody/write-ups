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

  - **DiceCTF HOPE 2022** --> catastrophe
    * [https://github.com/nobodyisnobody/write-ups/tree/main/DiceCTF%40HOPE.2022/pwn/catastrophe]()
    * *double free in fastbin, then overwrite libc strlen got entry with system() address*
    * *code execution when calling puts() function (that calls strlen...)*

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

  - **HSCTF 8 CTF 2021*** --> House of sice
    * [https://github.com/nobodyisnobody/write-ups/tree/main/HSCTF.8.CTF.2021/House.of.Sice]()
    * *double free vulnerability, using fastbin dup attack, then allocation on __free_hook*

  - **DownUnder CTF 2021*** --> DUCTF Note
    * [https://github.com/nobodyisnobody/write-ups/tree/main/DownUnderCTF.2021/pwn/DUCTFnote]()
    * *int8 overflow in edit function, then write in tcache metadata, then allocation on __free_hook*

  - **DigitalOverdose CTF 2021*** --> flavor
    * [https://github.com/nobodyisnobody/write-ups/tree/main/DigitalOverdose.2021/pwn/flavor]()
    * *double free vulnerability and uaf, then allocation on __free_hook*

  ### libc 2.29

  - **GDG Algiers CTF 2022** --> Notes Keeper
    * [https://github.com/nobodyisnobody/write-ups/tree/main/GDG.Algiers.CTF.2022/pwn/Notes.keeper]()
    * *use null byte overflow to make 0x118 chunk goes to tcache 0x20 size when freed*
    * *the do fastbin dup attack, to finally overwrite __free_hook*
    
  ### libc 2.27

  - **RaR CTF 2021** --> unintended
    * [https://github.com/nobodyisnobody/write-ups/tree/main/RaRCTF.2021/pwn/unintended]()
    * *heap overflow because of strlen usage, then make overlapping chunk & tcache poisonning*
    * *finally overwrite __free_hook*

  - **IJCTF 2021** --> ezpez
    * [https://github.com/nobodyisnobody/write-ups/tree/main/IJCTF.2021/pwn/ezpez]()
    * *double free on tcache_head to have allocation in unsorted, leak libc, double free on stdin to modify filedescriptor and leak flag*

  - **HSCTF 8 CTF 2021*** --> Use after freedom
    * [https://github.com/nobodyisnobody/write-ups/tree/main/HSCTF.8.CTF.2021/use_after_freedom]()
    * *unsorted bin attack, overwrite global_max_fast, then overwrite __free_hook*
 
  ### libc 2.25
  - **Tamil CTF 2021*** --> Vuln Storage
    * [https://github.com/nobodyisnobody/write-ups/blob/main/Tamil.CTF.2021/pwn/Vuln.Storage/]()


</details>

<details>
  <summary><strong>Code execution after exit</strong></summary>

  - **Imaginary CTF 2022** --> rope
    * [https://github.com/nobodyisnobody/write-ups/tree/main/imaginary.CTF.2022/pwn/rope]()
    * *code execution via overwriting _rtld_global+3848 , that is __rtld_lock_lock_recursive (GL(dl_load_lock));*
    * *and pivoting in _rtld_global , via gets() and setcontext gadget* 

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
    * *small echo server in assembly, very few gadgets --> ROP & sigrop*

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

  - **Hack.lu CTF 2022** --> byor
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Hack.lu.CTF.2022/pwn/byor]()
    * *libc-2.35 based fsop exploitation, _wide_data points on NULL chunk, we can overwrite stdout*
    * *code execution via _IO_wfile_underflow , we execute system('/bin/sh'),  new standard for FSOP*

  - **FCSC 2022** --> RPG
    * [https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2022/pwn/RPG]()
    * *heap overflow in FILE structure, then we use FSOP read/write to overwrite __free_hook*
    
</details>

<details>
  <summary><strong>restricted shellcode challenges</strong></summary>

  - **Redpwn CTF 2021** --> gelcode-2
    * [https://github.com/nobodyisnobody/write-ups/tree/main/RedpwnCTF.2021/pwn/gelcode-2]()
    * *shellcode with only opcodes from 0 to 5, and a seccomp that force open/read/write shellcode*

  - **MetaCTF 2021** --> sequential shellcode
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/Sequential.Shellcode]()
    * *shellcode where every byte must be bigger then the preceding one*

  - **Maple CTF 2022** --> EBCSIC
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MapleCTF.2022/pwn/EBCSIC]()
    * *shellcode alphanumeric but restricted to cp037 charset*

  - **FCSC 2022** --> palindrome
    * [https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2022/pwn/Palindrome]()
    * *need to write a palindrome shellcode, that can be read and executed in two direction*

  - **Aero CTF 2021** --> Shell Master 2
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Aero.CTF.2021/Shell.Master.2]()
    * *run and execute 16byte alphanumeric shellcodes*

</details>

<details>
  <summary><strong>Format string challenges</strong></summary>

  - **PBjar CTF 2021** --> wallstreet32
    * [https://github.com/nobodyisnobody/write-ups/tree/main/PBjar.CTF.2021/pwn/Wallstreet32]()
    * *restricted format string with many format chars forbidden, use trick '%*\n' to get a leak (libc-2.31 based)*

  - **MetaCTF 2021** --> Simple Format Returned
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/Simple.Format.Returned]()
    * *well classical format string, need bruteforce*

  - **Maple CTF 2022** --> printf
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MapleCTF.2022/pwn/printf]()
    * *well classical format string, need bruteforce*

  - **Imaginary CTF 2021** --> inkaphobia
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Imaginary.CTF.2021/pwn/inkaphobia]()
    * *well classical format string, need bruteforce*

  - **IJCTF 2021** --> baby sum
    * [https://github.com/nobodyisnobody/write-ups/tree/main/IJCTF.2021/pwn/baby-sum]()
    * *simple format string*

  - **FCSC 2022** --> Formatage
    * [https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2022/pwn/Formatage]()
    * *well classical format string, need bruteforce*

  - **DigitalOverdose CTF 2021*** --> uncurved
    * [https://github.com/nobodyisnobody/write-ups/tree/main/DigitalOverdose.2021/pwn/uncurved]()
    * *format string on heap with seccond that forbid execve, and bit a of bruteforce*

  - **Asis CTF Quals 2022*** --> Baby Scan II
    * [https://github.com/nobodyisnobody/write-ups/tree/main/ASIS.CTF.Quals.2022/pwn/Baby.scan.II]()
    * *abuse format string in snprintf to have a write anywhere primitive*
    * *then overwrite exit got entry with _start, then overwrite atoi with printf for leaks*
    * *then overwrite atoi() with system() for code execution*/

</details>

<details>
  <summary><strong>Various ROP challenges</strong></summary>

  - **MetaCTF 2021** --> An Attempt Was Made
    * [https://github.com/nobodyisnobody/write-ups/tree/main/MetaCtf.2021/pwn/A.Attempt.Was.Made]()
    * *restricted rop, execve forbidden, few gadgets (no libcsu_init gadget), use only add_gadget to forge gadgets*

  - **Hayyim CTF 2021** --> warmup
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Hayyim.CTF.2022/pwn/warmup]()
    * *simple rop challenge*

  - **Hayyim CTF 2021** --> cooldown
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Hayyim.CTF.2022/pwn/cooldown]()
    * *more restricted rop challenge*

  - **Fword CTF 2021** --> blacklist revenge
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Fword.CTF.2021/pwn/blacklist.revenge]()
    * *seccomp in place to forbid execve, no stdout/stderr output, so a mix of ROP+connect back shellcode*

  - **DefCamp CTF 2022** --> blindsight
    * [https://github.com/nobodyisnobody/write-ups/tree/main/DefCamp.CTF.2022/pwn/blindsight]()
    * *blind remote ROP with no binaries given*

</details>

<details>
  <summary><strong>ARM based challenges</strong></summary>

  - **LINE CTF 2022** --> simbox
    * [https://github.com/nobodyisnobody/write-ups/tree/main/LINE.CTF.2022/pwn/simbox]()
    * *ARM challenge based on gnu simulator 11.2 (with custom patch), we rop it, and dump flag*

</details>

<details>
  <summary><strong>Automatic exploit generation challenges</strong></summary>

  - **Imaginary CTF 2021** --> speedrun
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Imaginary.CTF.2021/pwn/speedrun]()
    * *automatic generated exploit, gets buffer overflow type*

</details>

<details>
  <summary><strong>VM Escape challenges</strong></summary>

  - **Fword CTF 2021** --> Peaky and the brain
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Fword.CTF.2021/pwn/peaky.and.the.brain]()
    * *funny challenge, web application written in python, convert an image to brainfuck language, then execute brainfuck code*
    * *oob write on stack in brainfuck interpreter, seccomp in place forbid execve, so open/read/write shellcode translated in brainfuck*

  - **CyberSecurityRumble CTF 2022** --> riscv-jit
    * [https://github.com/nobodyisnobody/write-ups/tree/main/CyberSecurityRumble.CTF.2022/pwn/riscv-jit]()
    * *escape from a riscv bson parser inside a riscv jit interpreter to a riscv shellcode,*
    * *then escape from a riscv just in time interpreter via a oob write in rwx zone, and execute x86 shellcode*

  - **CyberSecurityRumble CTF 2020** --> bflol
    * [https://github.com/nobodyisnobody/write-ups/tree/main/CyberSecurityRumble.CTF.2020/bflol]()
    * *oob read/write in a brainfuck interpreter , we dump our leaks on stack*
    * *then overwrite return address with a onegadget*

  - **404 CTF 2022** --> Changement d'architecture II
    * [https://github.com/nobodyisnobody/write-ups/tree/main/ASIS.CTF.Quals.2022/pwn/Baby.scan.II]()
    * *a sort of arm lite vm, oob read/write in registers access, that permit overwrite FILE structure*
    * *then we get code execution via FSOP*

  - **0CTF TCTF 2022** --> ezvm
    * [https://github.com/nobodyisnobody/write-ups/tree/main/0CTF.TCTF.2022/pwn/ezvm]()
    * *escape a stack machine type of vm, via an oob write, we leak an address on heap via program logic trick*
    * *then we get execution on exit, by forging a dtors_table in tls-storage and erasing random val at fs:0x30*

</details>

<details>
  <summary><strong>Uncategorized challenges (but worth reading)</strong></summary>

  - **Google CTF Quals 2022** --> FixedASLR
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Google.CTF.2022/pwn/FixedASLR]()
    * *great challenge, attack on LFSR based with a known output, to calculate canary (generated by the LFSR)*
    * *use a ROP and a SIGROP for shell execution*

  - **FCSC 2022** --> httpd
    * [https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2022/pwn/httpd]()
    * *interesting challenge, exploitation of syslog() format string vuln by child process, that exploit the parent process*
    * *child process http authentification has a buffer overflow in base64 decoding to a fixed buffer on stack*

  - **FCSC 2022** --> deflation
    * [https://github.com/nobodyisnobody/write-ups/tree/main/FCSC.2022/pwn/Deflation]()
    * *buffer overflow when decompressing zlib compressed data, then restricted ROP*

  - **Balsn CTF 2022** --> Asian Parents
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Balsn.CTF.2022/pwn/Asian.Parents]()
    * *interesting challenge where a parent process trace a child process to filter his syscalls via ptrace*

  - **Balsn CTF 2021** --> orxw
    * [https://github.com/nobodyisnobody/write-ups/tree/main/Balsn.CTF.2021/pwn/orxw]()
    * *interesting challenge where a parent can only write, and a child process can only open and read*
    * *stdin,stdout,stderr are closed, so we use time to extract flag content by testing each char, and blocking when right guess*

</details>


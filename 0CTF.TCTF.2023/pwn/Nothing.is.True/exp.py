#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import random, sys
import gmpy2

context.log_level = 'info'

# shortcuts
def sa(delim,data): return p.sendafter(delim,data)
def sla(delim,line): return p.sendlineafter(delim,line)

if args.DOCKER:
  host, port = "127.0.0.1", "3892"
else:
  host, port = "111.231.174.57", "3892"

def dopow():
  p.recvuntil('2^(2^', drop=True)
  t = int(p.recvuntil(')',drop=True),10)
  p.recvuntil('mod ',drop=True)
  n = int(p.recvuntil(' ',drop=True),10)
  oth = process(['./pow', str(t), str(n)]) # compile a.out from C code
  p.sendafter('answer: ', oth.recvline())
  oth.close()

p = remote(host,port)
if not args.DOCKER:
  dopow()
elf = open('./exp', 'rb').read()
sla('Size of your ELF: ', str(len(elf)))
sa('File:\n', elf)

p.interactive()


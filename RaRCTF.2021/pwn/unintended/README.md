Unintended was a heap challenge from RaRCTF.

the libc version was libc-2.27, which is the standard version for Ubuntu 18.04, is has tcache activated, and is vulnerable to many attacks.

It wasn't a hard challenge, but could be interesting to analyse for people beginning with heap exploitation.

first let's have a look at various binary protections:

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/perms.png)

ok , the program present to us a classic heap menu challenge..

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/menu.png)

while basically, permits to allocate a bloc, view it , delete it, and edit it...



### 1. Functional Analysis

**"Create a challenge"**

When we choose "Create a challenge", the program ask for a challenge number first:

We see in the code that we can create up to 10 challenges, (0 to 9). 

The bloc allocated address are stored in a challenges[] table, of 10 entries.

It checks if the index is in the 0 to 9 range, and if the challenges[index] entry is zero.

then it allocates a blocs of 0x30 bytes

in this bloc:
* at offset 0, it ask for "Challenge category" and store it as char string of max 16 bytes
* at offset 0x10, it ask for "Challenge name" and store it as char string of max 16 bytes
* at offset 0x20 it store a pointer to a second bloc, that you are first asked for its length (free) "Challenge Description Length"
* at offset 0x28 it store a number of point value.

so, it allocates a second bloc, with the given "Challenge Description Length",  store the address pointer of the bloc at offset 0x20 (of first bloc)
and it read the challenge description from user input, and store it in the newly allocated bloc.


**"Patch a challenge"**

well it is an edit "challenge description" function basically. You can only edit challenge in the "web" category.

It is presented as a patch vulnerability function, and in fact , that is where the vulnerabilty lies..

well let's have a look at IDA reverse output..

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/reverse1.png)


well.. do you see the vuln?

the program use the returned value of strlen, as the size for the read function.

if you use a bloc, with length ending by 8 (because of the length, of the metada), and fill it with data (no zeroes in)

the last byte , of you bloc, will touch the size value of the next bloc,.. and as strlen stop at the first zero byte encountered..

strlen, will return the length of the bloc plus the length of the prev_size entry..

so you will be able to edit the size of the next bloc, after you data..

let's try it, we will allocate a bloc of 0x28,  and a bloc of 0x70 sizes.

but remember the "Make Challenge" will allocate two blocs, for each challenge created, one of 0x30 bytes (true size 0x40 because of the metadat added),  
and one of the requested size for "Challenge description"

so with our python code:

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/python1.png)

let's see the result on gdb (with gef):
![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/gdb1.png)

you can see in the gdb picture, that our data 'a' char, 0x61 in ascii, reach the address with the size of the next bloc,  

it is the value 0x41 (in green on picture),  that indicates a bloc of 0x40 (plus bit 0 set for PREV_INUSE)

so if we call strlen, it will return us a size of 0x29 byte, instead of 0x28, the real size of our data.

With that vulnerability, we can edit the next bloc size.

We will explain later, how this can be abused , to obtain overlapping chunks..

that are chunks, that overlapped an another chunk after, and that will permit us to edit the next chunk metadata..


**"Deploy a challenge"**

this function, is a show chunks content function.

it checks if the requested bloc, is in the range 0 to 9, and if its address pointer in challenges[] table is non-null before showing it. 

(so it has no vulnerability by itself, but it will be important for us , to dump libc, and heap addresses..)

it prints the "Name" and "Category" entries, in the first 0x30 bytes chunk allocated for each challenge.

then it will print the Description , in the challenge description bloc allocated by us.


**"Take Down challenge"**

this function, is a delete chunks content function.

it checks if the requested bloc, is in the range 0 to 9, and if its address pointer in challenges[] table is non-null before deleting it. 

Then it will first free the chunks with the Challenge description,  then then 0x30 chunk with the challenge data inside (name, category, etc...)

then it will clear the challenges[] table entry, to prevent use after free, if the chunks..

**"Do Nothing"**

Well it does ...guess what ??  Nothing...then exits.. (which is a bit more than nothing in fact...)




### 2. Let"s Prepare for War.

First as the binary has PIE protection on, we need to leak libc base address & heap base address.

as we can choose the size of the chunk allocated,  depending on the requested size, we can allocate data in unsorted bin, or tcache, or even mmaped chunk before libc,

so this is a relatively easy task.

there are many ways to do it.  Let's first leak libc address.

There is no Use After Free (UAF) vulnerability in show chunk function, so we need to allocate a chunk again (same size) at the place we want to leak libc arena address,

and as malloc does not clear the chunk allocated, we only write one byte to the new allocated chunk (ideally the same that the LSB of 

libc arena address, 0xa0 in our case) to dump the full libc arena adress.

We will allocate a chunk of 0x428 bytes (chunk 'A'), it is bigger than tcache maximum chunk size, so it will be allocated in unsorted bin.

then we will allocate two 0x38 bytes (0x40 in tcache) chunks (named 'B' & 'C')

then we will free them.  The big chunk allocated in unsorted bin, when freed, will have it's BK & FD pointers, point to main_arena in libc.

with LSB of libc address always be 0xa0.. (easy to verify on gdb),  so we will allocate (immediatly after freeing them),

another bloc of the same size 0x428, with only a byte of 0xA0 as its data.. so that the libc main_arena address will not be corrupted.

And we can leak it, with the "Deploy Challenge" function.

```python
add(0,'web', 'A', 0x428, 'aaa', 1000)
add(1,'web', 'B', 0x38, 'aaa', 1000)
add(2,'web', 'C', 0x38, 'aaa', 1000)
free(0)
free(2)
free(1)
add(0,'web', 'A', 0x428, '\xa0', 1000)
deploy(0)
```


see the state of the heap after this operation.

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/leak1.png)

now we do the same for leaking an heap address, and calculate heap base address.

We allocate a chunk of 0x38 bytes, (0x40 with medata) , so it will be allocate at the same address,

and we use byte 0x80 for our LSB, (verified with gdb), to obtain a correct heap chunk address.

as it's offset from the beginning of the heap is constant, we substract it with 0x780 to obtain the beginning of the heap

```python
add(1,'X', 'B', 0x38, '\x80', 1000)
deploy(1)
```

see the state of the heap after this operation.

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/leak2.png)

you can see the LSB overwritten, and our calculation..

after all this, there are still two chunks previously free in tcache list as you can see at the bottom of the picture..

this is the bloc 'C' with it data bloc of 0x40 also..


### 2. Let's start the War !!!

Ok, at this point, we have all we need , we know the libc base address, and we know the heap base address.

This is all we need.

We are gonna try to have chunks overlapping, so that by editing a chunk we will edit the metadata and data of a previously freed chunk.

As there are no UAF vulnerability in edit function, it will be impossible to do it, without overlapping chunk.

Basically, this is the same attack that the one explained in the VERY GOOD github of Shellphish, named "how2heap"

https://github.com/shellphish/how2heap/blob/master/glibc_2.27/overlapping_chunks.c

I can recommand you to read, and study all the examples in this github, this is probably one of the best source of information, for heap exploitation.

One thing that complicates a bit the exploitation for us, is that when we allocate a new Challenge, two chunks are created each time.

One of 0x30 bytes and another that we can choose the size.. And for the attack to succeed, it need that the two chunks are adjacent.

Because we modify the size of the adjacent chunk. So if we have a 0x40 chunk in between, we cannot reach the size of the chunk that we control the content.

ok...well...

You remember that we have two chunks of 0x40 in tcache list, you can see them at the bottom of the previous picture.

These chunks, will save our lives :)  because the two next 0x30 chunk allocation request, will be served from the tcache list...

So the chunk, will be allocated at their old places, and not in between our big chunks allocation...

But you will see it in GDB...

of let's see the beginning ouf the attack..

```python
add(2,'web', 'A', 0x4f8, 'a'*0x4f8, 1000)
add(3,'web', 'B', 0x4f8, 'b'*0x4f8, 1000)
add(4,'web', 'C', 0x78, 'c'*0x78, 1000)
free(3)
patch(2,'A'*0x4f8+p16(0x581))
free(4)
payload = 'D'*0x530+p64(0)+p64(0x81)+p64(libc.symbols['__free_hook'])+p64(heap_base+0x10)
add(3,'web', 'D', 0x578, payload, 1000)
```

we allocate two big unsorted chunk of 0x4f8 bytes (they will be 0x500 bytes with metada)

followed by a tcache chunk of 0x78bytes  (0x80 in tcache)

we free the unsorted chunk in the middle, this is the one that we will attack, by overflowing into is size value while editing previous chunk.

we modify it's size, to 0x581, a bigger size that will overlap the tcache chunk 'C' just after...

then we free the tcache bloc 'C', to be able to modify it once freed..

and finally create an unsorted bloc of size 0x578 bytes (0x580 with metada).., that bloc will be allocated at the place of the 'B' chunk , that we have freed before, as the malloc system now believed that the old size (modified by us) was 0x580 also...

so what we have now?

we have a 0x580 bloc 'D' at index 3,  that will overlap the next chunk of 0x78 (0x80) size, that we freed before..

see the state of the heap at this point

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/heap3.png)

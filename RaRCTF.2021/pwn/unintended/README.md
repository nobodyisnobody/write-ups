Unintended was a heap challenge from RaRCTF.

the libc version was libc-2.27, which is the standard version for Ubuntu 18.04, is has tcache activated, and is vulnerable to many attacks.

It wasn't a hard challenge, but could be interesting to analyse for people beginning with heap exploitation.

first let's have a look at various binary protections:

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/perms.png)

ok , the program present to us a classic heap menu challenge..

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/menu.png)

while basically, permits to allocate a bloc, view it , delete it, and edit it...

###### 1. Functional Analysis

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


well.. do you the vuln?

the program use the returned value of strlen, as the size for the read function.

if you use a bloc, with length ending by 8 (because of the length, of the metada), and fill it with data (no zeroes in)

the last byte , of you bloc, will touch the size value of the next bloc,.. and as strlen stop at the first zero byte encountered..

strlen, will return the length of the bloc plus the length of the prev_size entry..

so you will be able to edit the size of the next bloc, after you data..

let's try it, we will allocate a bloc of 0x28,  and a bloc of 0x70 sizes.

but remember the "Make Challenge" will allocate two blocs, for each challenge created, one of 0x30 size and one of the requested size for "Challenge description"

so with our python code:

![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/python1.png)

let's see the result on gdb (with gef):
![](https://github.com/nobodyisnobody/write-ups/raw/main/RaRCTF.2021/pwn/unintended/pics/gdb1.png)

you can see in the gdb picture, that our data 'a' char, 0x61 in ascii, reach the size of the next bloc,  the value 0x41 (in green),

that indicates a bloc of 0x40 (plus bit 0 set for USED)

so if we call strlen, as it stops at the first zero byte, it will return us as size of 0x29 byte, instead of 0x28, the real size of our data.

And like that, we can edit the next bloc size.

That vulnerability will permit us to create blocs, that overlaps each other.. and to edit the contains of a next bloc that has been freed before,

to continue the attack, with a tcache poisonning attack.



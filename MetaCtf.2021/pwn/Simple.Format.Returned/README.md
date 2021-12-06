Simple Format Returned

was a pwn challenge from MetaCTF 2021.

It is a format string vulnerability. A classic.

The exploitation is classic also , but not easy as it needs to have a good ASLR to work.

We leak libc & stack address with the format string, and wait for the MSB byte of 32bit addresses to be small...

as it is not a blind format string, all the data we send , will be sent us back, so for the program not to timeout , it needs a small MSB byte in both libc & stack mapping address..

this could take time ,and numerous try...

to see a more in deth explanation on how format string exploitation works, how to have a return to main, etc, 

take a look at my previous write-up for another format string challenge:

[https://github.com/nobodyisnobody/write-ups/tree/main/DigitalOverdose.2021/pwn/uncurved](https://github.com/nobodyisnobody/write-ups/tree/main/DigitalOverdose.2021/pwn/uncurved)

it explains in details, how to exploit this...

the exploit code:

![](https://github.com/nobodyisnobody/write-ups/raw/main/MetaCtf.2021/pwn/Simple.Format.Returned/pics/code.png)

Here is the exploit in action (a bit edited it to cut the waiting parts...)

![](https://github.com/nobodyisnobody/write-ups/raw/main/MetaCtf.2021/pwn/Simple.Format.Returned/pics/format.gif)

*nobodyisnobody still pwning things...*


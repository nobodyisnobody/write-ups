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

#### **Smuggler's cove**

was a pwn challenge from Defcon Quals 2022.

It was a pwn challenge about exploiting a lua jit interpreter.

A shared library containing the lua jit interpreter was given, libluajit-5.1.so.2.

and two programs:

- cove  and  cove.c (its sources)

- dig_up_the_loot and  dig_up_the_loot.c (its sources),  a simple program that need to be executed with these arguments:                             

  `./dig_up_the_loot x marks the spot`

executing this way will display the flag.



The cove program, will take a input lua source code , of a maximum size of 433 bytes.

and execute it via the lua library.








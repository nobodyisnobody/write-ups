Here is a 3 solutions (choose your preferred one) write-up for CRAPSemu challenge

My teammate Shir0 start reversing Crapsemu,
I joined him because the end of the ctf was soon.. and time was running....

first we start studying the disassembly of the CRAPS program

```
0x0:    add r29 = r0, 0x200
0x4:    mov r0 = 0x20 // probably just a raw data -> b' \x00\x00\x01'
0x8:    orcc r1 = r1, 0x3a
0xc:    sub r29 = r29, 0x1
0x10:    st r1 = r29, r0
0x14:    "b'ord\x01'"
0x18:    orcc r1 = r1, 0x77
0x1c:    sub r29 = r29, 0x1
0x20:    st r1 = r29, r0
0x24:    "b'ass\x01'"
0x28:    orcc r1 = r1, 0x50
0x2c:    sub r29 = r29, 0x1
0x30:    st r1 = r29, r0
0x34:    add r1 = r0, 0x1
0x38:    orcc r2 = r1, r0
0x3c:    orcc r3 = r29, r0
0x40:    add r4 = r0, 0xa
0x44:    syscall
0x48:    Unknown: 0x82184001
0x4c:    orcc r2 = r1, r0
0x50:    add r3 = r0, 0x100
0x54:    add r4 = r0, 0x18
0x58:    syscall
0x5c:    add r29 = r0, 0x200
0x60:    mov r0 = 0x321695 // probably just a raw data -> b'\x95\x162\x01'
0x64:    orcc r1 = r1, 0x3e
0x68:    sub r29 = r29, 0x1
0x6c:    st r1 = r29, r0
0x70:    mov r0 = 0x2740af // probably just a raw data -> b"\xaf@'\x01"
0x74:    orcc r1 = r1, 0x39
0x78:    sub r29 = r29, 0x1
0x7c:    st r1 = r29, r0
0x80:    "b'\xc5hw\x01'"
0x84:    orcc r1 = r1, 0x3c
0x88:    sub r29 = r29, 0x1
0x8c:    st r1 = r29, r0
0x90:    "b'\xc1jL\x01'"
0x94:    orcc r1 = r1, 0x20
0x98:    sub r29 = r29, 0x1
0x9c:    st r1 = r29, r0
0xa0:    mov r0 = 0x290dab // probably just a raw data -> b'\xab\r)\x01'
0xa4:    orcc r1 = r1, 0x4e
0xa8:    sub r29 = r29, 0x1
0xac:    st r1 = r29, r0
0xb0:    "b'\xa0vA\x01'"
0xb4:    orcc r1 = r1, 0x5e
0xb8:    sub r29 = r29, 0x1
0xbc:    st r1 = r29, r0
0xc0:    Unknown: 0x80180005
0xc4:    bl
0xc8:    orcc r6 = r6, 0xd
0xcc:    subcc r0 = r29, 0x200
0xd0:    Unknown: 0x2200000a
0xd4:    ld r4 = r29, r0
0xd8:    add r29 = r29, 0x1
0xdc:    Unknown: 0x88190006
0xe0:    ld r2 = r3, r0
0xe4:    add r3 = r3, 0x1
0xe8:    subcc r0 = r4, r2
0xec:    Unknown: 0x23fffff8
0xf0:    Unknown: 0x8a116001
0xf4:    Unknown: 0x31fffff6
0xf8:    subcc r0 = r5, r0
0xfc:    Unknown: 0x22000019
0x100:    orcc r29 = r29, 0x200
0x104:    mov r0 = 0xa2e64 // probably just a raw data -> b'd.\n\x01'
0x108:    orcc r1 = r1, 0x72
0x10c:    sub r29 = r29, 0x1
0x110:    st r1 = r29, r0
0x114:    "b'swo\x01'"
0x118:    orcc r1 = r1, 0x73
0x11c:    sub r29 = r29, 0x1
0x120:    st r1 = r29, r0
0x124:    "b' pa\x01'"
0x128:    orcc r1 = r1, 0x67
0x12c:    sub r29 = r29, 0x1
0x130:    st r1 = r29, r0
0x134:    "b'ron\x01'"
0x138:    orcc r1 = r1, 0x57
0x13c:    sub r29 = r29, 0x1
0x140:    st r1 = r29, r0
0x144:    add r1 = r0, 0x1
0x148:    orcc r2 = r1, r0
0x14c:    orcc r3 = r29, r0
0x150:    add r4 = r0, 0x10
0x154:    syscall
0x158:    add r2 = r0, 0x1
0x15c:    Unknown: 0x3000001b
0x160:    orcc r29 = r29, 0x200
0x164:    add r1 = r0, 0xa
0x168:    sub r29 = r29, 0x1
0x16c:    st r1 = r29, r0
0x170:    mov r0 = 0x21736e // probably just a raw data -> b'ns!\x01'
0x174:    orcc r1 = r1, 0x6f
0x178:    sub r29 = r29, 0x1
0x17c:    st r1 = r29, r0
0x180:    "b'ati\x01'"
0x184:    orcc r1 = r1, 0x6c
0x188:    sub r29 = r29, 0x1
0x18c:    st r1 = r29, r0
0x190:    "b'atu\x01'"
0x194:    orcc r1 = r1, 0x72
0x198:    sub r29 = r29, 0x1
0x19c:    st r1 = r29, r0
0x1a0:    "b'ong\x01'"
0x1a4:    orcc r1 = r1, 0x43
0x1a8:    sub r29 = r29, 0x1
0x1ac:    st r1 = r29, r0
0x1b0:    add r1 = r0, 0x1
0x1b4:    orcc r2 = r1, r0
0x1b8:    orcc r3 = r29, r0
0x1bc:    add r4 = r0, 0x11
0x1c0:    syscall
0x1c4:    Unknown: 0x84188002
0x1c8:    add r1 = r0, 0x2
0x1cc:    syscall

```

well a bit ugly I know :)

Reading this disassembly, 

we guess the program was outputting 'password: ', reading input, comparing to a static data transformed in a way or another,

maybe xor?  and if password is correct it outputs 'Congratulations...'

but there were some instruction unknown, so I start reversing the first one with Ghidra.

0x48:    Unknown: 0x82184001

it was this function, which is basically an xor, between to registers stored in a third destination register

![](https://imgur.com/8b74opp.png)

or in the assembly output

![](https://imgur.com/84mmVaE.png)

I first launch a angr script to try to find an input that will print the 'Congratulations' string.. but as it was a bit slow, I forget it running in a terminal window :)

So I have the idea to put a breakpoint, at the xor instruction at 0x1cbc, (or 0x1cbe just after)

and to see what exactly was xored...?

I just launched gdb (gef variant)  with the breakpoint..

gdb-gef -ex 'b main' -ex 'c' -ex 'pie breakpoint *0x1cbc' -ex 'pie run' ./crapsemu

the first xor, was 0xa with 0xa , not interesting...

then the second one...BINGO... the Flag start to appear.. complete after 6 breakpoint stops (6x 4bytes each time , 24chars)

echo -e '\x53\x50\x41\x52\x43\x5b\x3a\x3a\x2d\x31\x5d\x5f\x31\x35\x5f\x64\x34\x5f\x77\x34\x33\x65\x21\x21' 

SPARC[::-1]_15_d4_w43e!!

ok got it..

then I wrote a qiling script to automatically resolve it.. (set up a correct rootfs path to run it)

```
import sys
sys.path.append("..")

from qiling import Qiling
from qiling.const import QL_VERBOSE

buff = b''
def xor_func(ql):
  global buff
  if (ql.reg.ecx):
    buff += ql.reg.ecx.to_bytes(4,'little')
    print('FLAG: '+buff.decode('UTF-8'))

if __name__ == "__main__":
    ql = Qiling(["./crapsemu"], "rootfs/x8664_linux", verbose=QL_VERBOSE.OFF, stdin="pipo")
    ql.hook_address(xor_func, 0x555555555cbe)
    ql.run()
```

works great as you can see...

![](https://imgur.com/Kr1U2Yx.png)

then after the CTF was finished...

I have a look to my terminal windows, where angr was running (forgot it totally...)

and guess what I see :)

![](https://imgur.com/y6xpCKm.png)

Well angr resolved it also..but I didn't see it...

so here is the angr script to resolve it, for those interested...

```
import angr
import claripy

def main():
    
    for i in range(16, 28):
        base_addr=0x400000
        input_len = i

        proj = angr.Project('./crapsemu', main_opts={'base_addr': base_addr})

        flag_chars = [claripy.BVS('flag_%i' % i, 8) for i in range(input_len)]
        flag = claripy.Concat( *flag_chars + [claripy.BVV(b'\n')]) # Add \n for scanf() to accept the input

        st = proj.factory.full_init_state(
            args='./crapsemu',
            stdin=flag, 
            add_options=angr.options.unicorn
        )

        for byte in flag_chars:
            st.solver.add(byte >= b"\x20")
            st.solver.add(byte <= b"\x7e")

        sm = proj.factory.simulation_manager(st)
        sm.run()

        y = []
        for x in sm.deadended:
            if b'Congratulations' in x.posix.dumps(1):
                y.append(x)

        for s in y:
            flag = ''.join([chr(s.solver.eval(k)) for k in flag_chars])
            print("Flag: %s" % flag)


if __name__ == '__main__':
    main()
```

*Nobodyisnobody for RootMeUpBeforeYouGoGo*


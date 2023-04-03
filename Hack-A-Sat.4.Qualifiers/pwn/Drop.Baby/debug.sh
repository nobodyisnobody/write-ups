sudo gdb-multiarch -ex source ./gef/gef.py -ex set architecture riscv:rv32 -ex gef-remote localhost 1235 -ex b *0x10fa4 -ex c ./drop-baby

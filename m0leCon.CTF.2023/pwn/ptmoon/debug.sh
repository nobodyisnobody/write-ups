gdb -ex 'source ~/gdb.plugins/gef.bata24.git/gef.py' -ex 'handle SIGUSR1 nostop' -ex 'target remote 127.0.0.1:1235' -ex 'file qemu-system-x86_64' -ex 'c'


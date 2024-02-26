#!/bin/sh
gdb -ex 'source ~/gdb.plugins/gef.bata24.git/gef.py' -ex 'aslr on' -ex 'b virtio_note_device_realize' -ex 'b virtio_note_handle_req' -ex 'run' --args ./qemu-system-x86_64 \
    -L ./bin/ \
    -m 64M \
    -cpu kvm64,+smep,+smap \
    -kernel bzImage \
    -device virtio-note,disable-legacy=on \
    -drive file=rootfs.ext3,format=raw \
    -drive file=filesystem.ext2,format=raw \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -sandbox on,spawn=deny \
    -append "root=/dev/sda rw init=/init console=ttyS0 kaslr loglevel=3 oops=panic panic=-1"

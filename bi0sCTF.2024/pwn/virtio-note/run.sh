#!/bin/sh
./qemu-system-x86_64 \
    -L ./bin/ \
    -m 64M \
    -cpu kvm64,+smep,+smap \
    -kernel bzImage \
    -device virtio-note,disable-legacy=on \
    -drive file=rootfs.ext3,format=raw \
    -drive file=$1,format=raw \
    -snapshot \
    -nographic \
    -monitor /dev/null \
    -no-reboot \
    -sandbox on,spawn=deny \
    -append "root=/dev/sda rw init=/init console=ttyS0 kaslr loglevel=3 oops=panic panic=-1" \
#    -virtfs local,path=/home/interzone/work.challenges/0000.bi0sCTF.2024/pwn/virtio-note/files/exploit,mount_tag=host0,security_model=passthrough,id=host0

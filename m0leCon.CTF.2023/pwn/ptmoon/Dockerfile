FROM ubuntu:23.10

COPY qemu-8.1.1-patched /build
COPY ubuntu-23.10.1-desktop-amd64.iso /img/ubuntu-23.10.1-desktop-amd64.iso

WORKDIR /build
RUN apt-get update && apt-get install -y wget xz-utils git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev ninja-build meson libslirp-dev python3-venv flex bison gdbserver
RUN ./configure --enable-slirp --enable-debug && cd build && make -j

COPY flag.txt /flag.txt

ENTRYPOINT gdbserver 127.0.0.1:1234 /build/build/qemu-system-x86_64 -enable-kvm -cdrom '/img/ubuntu-23.10.1-desktop-amd64.iso' -monitor none -serial stdio -net nic,model=virtio -net user,hostfwd=tcp::22-:22 -device vmware-svga -m 2048M -smp 2 -vnc 0.0.0.0:0

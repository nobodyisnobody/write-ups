#!/bin/bash

FLAG_SECRET=$(head /dev/urandom | LC_ALL=C tr -dc A-Za-z0-9 | head -c 40)

mv /home/pwn/flag.txt /home/pwn/flag_$FLAG_SECRET.txt

chmod 440 /home/pwn/flag_$FLAG_SECRET.txt && chmod 550 /home/pwn/chall && chown root:pwn /home/pwn/flag_$FLAG_SECRET.txt

socat -T60 "TCP-LISTEN:4444,reuseaddr,fork,su=pwn" "EXEC:/home/pwn/chall,pty,raw,stderr,echo=0"
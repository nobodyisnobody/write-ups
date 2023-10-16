#!/bin/sh
docker run -it --rm --cap-add sys_ptrace -p 1234:1234 -p 1440:1440 pong

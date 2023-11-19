FROM ubuntu:22.04@sha256:b492494d8e0113c4ad3fe4528a4b5ff89faa5331f7d52c5c138196f69ce176a6 AS base
COPY readflag /readflag
RUN  chown root:root /readflag && chmod 111 /readflag
WORKDIR /app
COPY babysbx  run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=3000 JAIL_CPU=100 JAIL_MEM=10M

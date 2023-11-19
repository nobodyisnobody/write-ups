FROM ubuntu:22.04@sha256:b492494d8e0113c4ad3fe4528a4b5ff89faa5331f7d52c5c138196f69ce176a6 AS base
WORKDIR /app
COPY devpro run
RUN chmod +x run
RUN  echo "FLAG{*** REDACTED ***}" > /flag.txt
RUN  mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=30000 JAIL_CPU=100 JAIL_MEM=10M

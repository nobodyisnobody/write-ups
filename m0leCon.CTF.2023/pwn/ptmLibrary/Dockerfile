FROM ubuntu:22.04

RUN apt-get update && apt-get upgrade -y
RUN apt-get install -y socat wget gdbserver
RUN apt-get install -y libssl-dev

RUN useradd -ms /bin/sh pwn

WORKDIR /home/pwn

COPY ./chall ./

COPY ./flag.txt ./

COPY ./entrypoint.sh ./

RUN chown -R root:pwn /home/pwn && chmod 750 /home/pwn  && chmod 550 entrypoint.sh

CMD ["/home/pwn/entrypoint.sh"]

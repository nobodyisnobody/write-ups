FROM ubuntu:18.04


RUN apt-get update && apt-get install -y python3-pip gdbserver nano sharutils

RUN pip3 install Flask

RUN useradd -ms /bin/bash user

RUN mkdir -p /home/user/app
COPY ./src /home/user/app
COPY --chown=root:root libc-2.27.so /lib/x86_64-linux-gnu/libc-2.27.so
RUN chmod 755 /lib/x86_64-linux-gnu/libc-2.27.so
RUN chown -R user:user /home/user/app

USER user
EXPOSE 5000

ENTRYPOINT python3 /home/user/app/main.py

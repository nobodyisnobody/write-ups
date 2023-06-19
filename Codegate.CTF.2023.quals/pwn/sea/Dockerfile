FROM ubuntu@sha256:b795f8e0caaaacad9859a9a38fe1c78154f8301fdaf0872eaf1520d66d9c0b98

ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update -y > /dev/null
RUN apt-get upgrade -y > /dev/null
RUN apt-get install xinetd gdbserver -y > /dev/null

RUN useradd -ms /bin/bash user
ADD ./share /home/user
RUN echo "#!/bin/bash\ngdbserver 127.0.0.1:1235 /home/user/sea" \
        > /home/user/run.sh
RUN chown -R root:user /home/user
RUN chmod -R 750 /home/user

RUN echo "service sea\n{\n\tdisable = no\n\tflags = REUSE\n\tsocket_type = stream\n\tprotocol = tcp\n\tuser = user\n\twait = no\n\tserver = /home/user/run.sh\n\ttype = UNLISTED\n\tport = 45510\n}" \
        > /etc/xinetd.d/sea
CMD ["/usr/sbin/xinetd", "-dontfork"]

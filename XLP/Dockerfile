FROM ubuntu:jammy

RUN apt-get update && \
    apt-get install -y build-essential \
                        zlib1g-dev libevent-dev \
                        libelf-dev libc6-dev-i386 \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir /XLP
WORKDIR /disprotrack

ADD bin/ bin/
ADD src/ src/

WORKDIR /disprotrack/src
RUN make -f xlp.mk
ENTRYPOINT [ "./xlp" ]
CMD ["-c"]
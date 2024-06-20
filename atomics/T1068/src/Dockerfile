FROM ubuntu:xenial-20190425
RUN apt-get update && apt-get install -y policykit-1=0.105-14.1 curl gcc
RUN useradd -m user
USER user
WORKDIR /home/user
ENTRYPOINT ["tail", "-f", "/dev/null"]


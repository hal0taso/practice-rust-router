FROM ubuntu:22.04

WORKDIR /app
ENV APP_HOME=/app

RUN chmod u+x $APP_HOME/   
RUN chmod u+x $APP_HOME/entrypoint.sh

RUN apt update
RUN apt install -y vim iputils-ping iproute2 traceroute tcpdump
RUN "/bin/bash"

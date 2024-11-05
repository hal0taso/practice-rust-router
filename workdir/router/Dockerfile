FROM ubuntu:22.04

WORKDIR /app
ENV APP_HOME=/app

# Add execution priviledge of entrypoint
RUN chmod u+x $APP_HOME/   
RUN apt update
RUN apt install -y emacs iputils-ping iproute2 traceroute tcpdump net-tools gcc make
RUN "/bin/bash"

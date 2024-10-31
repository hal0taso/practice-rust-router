FROM rust:1.72
FROM gcc:4.9

WORKDIR /app
ENV APP_HOME=/app

# Add execution priviledge of entrypoint
RUN chmod u+x $APP_HOME/   
RUN chmod u+x $APP_HOME/entrypoint.sh

RUN apt update
RUN apt install -y vim iputils-ping iproute2 traceroute tcpdump net-tools
RUN "/bin/bash"

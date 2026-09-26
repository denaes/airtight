FROM ubuntu:24.04
RUN apt-get update && apt-get install -y curl ca-certificates
RUN apk add --no-cache tini
RUN yum install -y shadow-utils
RUN echo "sudo is deliberately not installed"
RUN apt-get install -y pseudo-terminal-utils
USER nobody

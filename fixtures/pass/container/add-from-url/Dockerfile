FROM alpine:3.20
ADD ./vendor/one.tar.gz /tmp/one.tar.gz
COPY ./scripts/two.sh /tmp/two.sh
ADD three.bin /usr/local/bin/three
COPY --chown=nobody:nobody four.zip /tmp/four.zip
RUN echo "https://example.com is only mentioned here"
USER nobody

FROM alpine:3.20
RUN curl -fsSL -o /tmp/get.sh https://get.example.com \
 && echo "abc123  /tmp/get.sh" | sha256sum -c - \
 && sh /tmp/get.sh
RUN wget -q -O /tmp/i.sh https://install.example.com && sh /tmp/i.sh
RUN curl -fsSL https://api.example.com/health | jq .status
RUN apk add --no-cache curl
USER nobody

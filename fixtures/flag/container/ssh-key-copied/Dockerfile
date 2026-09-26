FROM alpine:3.20
COPY id_rsa /root/.ssh/id_rsa
ADD deploy.pem /etc/ssl/deploy.pem
COPY --chown=root:root id_ed25519 /root/.ssh/
COPY certs/client.p12 /etc/ssl/client.p12
USER nobody

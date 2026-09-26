FROM alpine:3.20
COPY ca.crt /etc/ssl/certs/ca.crt
COPY public.pub /root/.ssh/authorized_keys
RUN --mount=type=ssh git clone git@example.com:org/repo.git
COPY app.js /app/app.js
COPY package.json /app/package.json
USER nobody

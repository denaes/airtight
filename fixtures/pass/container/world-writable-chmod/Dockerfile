FROM alpine:3.20
RUN chmod 755 /app/data
RUN chmod -R 750 /var/log/app
RUN chown -R nobody:nobody /tmp/x && chmod 700 /tmp/x
RUN chmod 644 /etc/app.conf
RUN chmod +x /usr/local/bin/entrypoint
USER nobody

FROM node:20-alpine
USER root
RUN apk add --no-cache tini
USER root
COPY . /app
USER 0
RUN chown -R 0:0 /app
USER root
CMD ["node", "/app/server.js"]

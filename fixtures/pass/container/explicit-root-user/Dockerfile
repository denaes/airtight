FROM node:20-alpine
USER root
RUN apk add --no-cache tini

FROM node:20-alpine
COPY --from=0 /sbin/tini /sbin/tini
USER node
USER 10001
CMD ["node", "server.js"]

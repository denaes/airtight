FROM node:20-alpine
WORKDIR /app
COPY --chown=node:node . .
RUN npm ci --omit=dev
USER node
CMD ["node", "server.js"]

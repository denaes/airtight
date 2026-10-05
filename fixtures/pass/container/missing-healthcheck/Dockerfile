FROM node:20-alpine
WORKDIR /app
COPY . .
HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:3000/health || exit 1
CMD ["node", "server.js"]

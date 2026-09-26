FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
CMD ["node", "server.js"]

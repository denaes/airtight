FROM alpine:3.20
ARG API_KEY
ENV API_KEY=$API_KEY
ARG NPM_TOKEN
ENV NODE_ENV=production
ENV LOG_LEVEL=info
RUN --mount=type=secret,id=npmrc npm ci
USER nobody

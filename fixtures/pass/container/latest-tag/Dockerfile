FROM node:20.11.1-alpine3.19 AS a
FROM python:3.12.4-slim AS b
FROM golang:1.23.2 AS c
FROM ubuntu:24.04
FROM a
USER nobody
CMD ["true"]

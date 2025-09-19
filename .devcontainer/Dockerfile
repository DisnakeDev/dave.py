FROM mcr.microsoft.com/devcontainers/python:3.12-bookworm

RUN apt-get update \
 && apt-get install -y build-essential cmake git curl zip nasm golang-go \
 && apt-get clean

 COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

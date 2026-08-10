FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

ARG OCSERV_VERSION=1.3.0-2

COPY debian.sources /etc/apt/sources.list.d/debian.sources

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ocserv="${OCSERV_VERSION}" iproute2 \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 443/tcp 443/udp

ENTRYPOINT ["ocserv", "-f", "-d", "4", "-c", "/fixture/ocserv.conf"]

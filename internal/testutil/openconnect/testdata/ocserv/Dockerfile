FROM debian:trixie-slim@sha256:cedb1ef40439206b673ee8b33a46a03a0c9fa90bf3732f54704f99cb061d2c5a

ARG OCSERV_VERSION=1.3.0-2
ARG SOCAT_VERSION=1.8.0.3-1

COPY debian.sources /etc/apt/sources.list.d/debian.sources

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ocserv="${OCSERV_VERSION}" iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update \
    && apt-get install --yes --no-install-recommends socat="${SOCAT_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 443/tcp 443/udp

ENTRYPOINT ["sh", "-c", "socat TCP4-LISTEN:18080,reuseaddr,fork EXEC:/bin/cat & socat UDP4-RECVFROM:15353,reuseaddr,fork EXEC:/bin/cat & exec ocserv -f -d 4 -c /fixture/ocserv.conf"]

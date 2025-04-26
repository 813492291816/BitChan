FROM alpine:3.19.1

ENV TORVER="tor-0.4.9.2-alpha"
ENV TORLOC="https://www.torproject.org/dist/${TORVER}.tar.gz"

RUN apk update \
    && apk --no-cache add automake autoconf bash build-base gcc gnupg wget libevent libevent-dev libressl libressl-dev nss-dev xz-libs xz-dev zlib zlib-dev zstd zstd-libs zstd-dev \
    && wget --retry-connrefused --waitretry=5 --read-timeout=20 --timeout=20 -t 5 --continue -O /tmp/${TORVER}.tar.gz ${TORLOC} \
    && cd /tmp \
    && tar xvzf ${TORVER}.tar.gz \
    && cd /tmp/${TORVER} \
    && ./configure --enable-nss --enable-gpl \
    && make \
    && make install \
    && rm -rf /tmp/${TORVER}.tar.gz \
    && rm -rf /tmp/${TORVER} \
    && apk --purge del automake autoconf build-base gcc

RUN mkdir -p /root/.tor
RUN chown -R root /root/.tor

COPY ./docker/tor/torrc /torrc
COPY ./docker/tor/tor_setup.sh /tor_setup.sh

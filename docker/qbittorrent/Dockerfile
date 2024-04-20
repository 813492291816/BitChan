FROM alpine:3.19.1

ENV QB_HOME="/i2p_qb"
ENV HOST_USER_ID=1001
ENV HOST_GROUP_ID=1001

RUN apk update \
    && apk add autoconf automake boost-dev build-base cmake curl git libtool linux-headers perl pkgconf python3 python3-dev \
    qt5-qtbase-dev qt5-qttools-dev qt5-qtsvg-dev re2c ninja tar icu-dev openssl-dev ufw zlib-dev

# Commit 74bc93a37a5e31c78f0aa02037a68fb9ac5deb41 v2.0.10
RUN git clone --shallow-submodules --recurse-submodules https://github.com/arvidn/libtorrent.git ./libtorrent \
    && cd ./libtorrent \
    && git checkout 74bc93a37a5e31c78f0aa02037a68fb9ac5deb41 \
    && cmake -Wno-dev -G Ninja -B build \
    -D CMAKE_BUILD_TYPE="Release" \
    -D CMAKE_CXX_STANDARD=17 \
    -D CMAKE_INSTALL_LIBDIR="lib" \
    -D CMAKE_INSTALL_PREFIX="/usr/local" \
    && cmake --build build \
    && cmake --install build \
    && cd .. \
    && rm -rf ./libtorrent

RUN git clone https://github.com/mikroskeem/libexecinfo.git ./libexecinfo \
    && cd ./libexecinfo \
    && git checkout d79eee9b042198a841411668368fcad18a3da506 \
    && make PREFIX='/usr' all \
    && make PREFIX='/usr' install \
    && cd .. \
    && rm -rf ./libexecinfo

# Commit 785320e7f6a5e228caf817b01dca69da0b83a012 v4.6.4
RUN git clone --shallow-submodules --recurse-submodules https://github.com/qbittorrent/qBittorrent.git ./qbittorrent \
    && cd ./qbittorrent \
    && git checkout 785320e7f6a5e228caf817b01dca69da0b83a012 \
    && cmake -Wno-dev -G Ninja -B build \
    -D GUI=OFF \
    -D CMAKE_BUILD_TYPE="release" \
    -D CMAKE_CXX_STANDARD=17 \
    -D CMAKE_CXX_STANDARD_LIBRARIES="/usr/lib/libexecinfo.so" \
    -D CMAKE_INSTALL_PREFIX="/usr/local" \
    && cmake --build build \
    && cmake --install build \
    && cd .. \
    && rm -rf ./qbittorrent

RUN apk --purge del boost-dev build-base

COPY docker/qbittorrent/entrypoint.sh /entrypoint.sh
COPY docker/qbittorrent/qBittorrent.conf /qBittorrent.conf

RUN chmod a+rx /entrypoint.sh

EXPOSE 8080

ENTRYPOINT [ "/entrypoint.sh" ]

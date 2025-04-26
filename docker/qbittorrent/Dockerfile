FROM alpine:3.19.1

ENV QB_HOME="/i2p_qb"
ENV HOST_USER_ID=1001
ENV HOST_GROUP_ID=1001

RUN apk update \
    && apk add autoconf automake boost-dev build-base cmake curl git libtool linux-headers perl pkgconf python3 python3-dev \
    qt6-qtbase-dev qt6-qttools-dev qt6-qtsvg-dev re2c ninja tar icu-dev openssl-dev ufw zlib-dev

# Commit 74bc93a37a5e31c78f0aa02037a68fb9ac5deb41 v2.0.10
# Commit 9d7443f467147d1784fb7516d2a882db1abb5a8b v2.0.11
RUN git clone --progress --verbose --shallow-submodules --recurse-submodules https://github.com/arvidn/libtorrent.git ./libtorrent \
    && cd ./libtorrent \
    && git checkout 9d7443f467147d1784fb7516d2a882db1abb5a8b \
    && cmake -Wno-dev -G Ninja -B build \
    -D CMAKE_BUILD_TYPE="Release" \
    -D CMAKE_CXX_STANDARD=17 \
    -D CMAKE_INSTALL_LIBDIR="lib" \
    -D CMAKE_INSTALL_PREFIX="/usr/local" \
    && cmake --build build \
    && cmake --install build \
    && cd .. \
    && rm -rf ./libtorrent

RUN git clone --progress --verbose https://github.com/mikroskeem/libexecinfo.git ./libexecinfo \
    && cd ./libexecinfo \
    && git checkout d79eee9b042198a841411668368fcad18a3da506 \
    && make PREFIX='/usr' all \
    && make PREFIX='/usr' install \
    && cd .. \
    && rm -rf ./libexecinfo

# Commit c01265c4cffe98db2ee2fba651f7f254ca8afbec v4.6.6
# Commit 2d67729617fc3f5bd9cfb71953d45f73a8c1a617 v5.0.0rc1
# Commit 94136262a84293da0d8504724e7143df0d0baa12 v5.0.1
# Commit d96ab6ba849ae722d2abb1d94c760283f7b51135 v5.1.0beta1
# Commit bc7d5c1f8f50fe1b4b09c3653eeb490d8733edb4 v5.1.0rc1
RUN git clone --progress --verbose --shallow-submodules --recurse-submodules https://github.com/qbittorrent/qBittorrent.git ./qbittorrent \
    && cd ./qbittorrent \
    && git checkout bc7d5c1f8f50fe1b4b09c3653eeb490d8733edb4 \
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

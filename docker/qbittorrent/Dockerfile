FROM alpine:3.23.2 AS base

ENV QB_HOME="/i2p_qb" \
    HOST_USER_ID=1001 \
    HOST_GROUP_ID=1001

RUN apk --no-cache --update-cache upgrade

# run-time dependencies
RUN apk --no-cache add \
  7zip \
  bash \
  curl \
  libcrypto3 \
  libssl3 \
  qt6-qtbase \
  qt6-qtbase-sqlite \
  tini \
  tzdata \
  ufw \
  zlib

# image for building
FROM base AS builder

ENV QBT_VERSION="5.1.4" \
    BOOST_VERSION_MAJOR="1" \
    BOOST_VERSION_MINOR="86" \
    BOOST_VERSION_PATCH="0" \
    LIBBT_VERSION="RC_1_2" \
    LIBBT_CMAKE_FLAGS=""

# alpine linux packages:
# https://git.alpinelinux.org/aports/tree/community/libtorrent-rasterbar/APKBUILD
# https://git.alpinelinux.org/aports/tree/community/qbittorrent/APKBUILD
RUN apk add \
  cmake \
  git \
  g++ \
  make \
  ninja \
  openssl-dev \
  qt6-qtbase-dev \
  qt6-qtbase-private-dev \
  qt6-qttools-dev \
  zlib-dev

# compiler, linker options:
# https://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html
# https://gcc.gnu.org/onlinedocs/gcc/Link-Options.html
# https://sourceware.org/binutils/docs/ld/Options.html
ENV CFLAGS="-pipe -fstack-clash-protection -fstack-protector-strong -fno-plt -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS" \
    CXXFLAGS="-pipe -fstack-clash-protection -fstack-protector-strong -fno-plt -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -D_GLIBCXX_ASSERTIONS" \
    LDFLAGS="-gz -Wl,-O1,--as-needed,--sort-common,-z,now,-z,pack-relative-relocs,-z,relro"

# prepare boost
RUN cd / && \
  wget -O boost.tar.gz "https://archives.boost.io/release/$BOOST_VERSION_MAJOR.$BOOST_VERSION_MINOR.$BOOST_VERSION_PATCH/source/boost_${BOOST_VERSION_MAJOR}_${BOOST_VERSION_MINOR}_${BOOST_VERSION_PATCH}.tar.gz" && \
  tar -xf boost.tar.gz && \
  mv boost_* boost && \
  cd boost && \
  ./bootstrap.sh && \
  ./b2 stage --stagedir=./ --with-headers

# build libtorrent
# Commit 9d7443f467147d1784fb7516d2a882db1abb5a8b v2.0.11
RUN cd / && \
  git clone --progress --verbose --shallow-submodules --recurse-submodules https://github.com/arvidn/libtorrent.git ./libtorrent && \
  cd ./libtorrent && \
  git checkout 9d7443f467147d1784fb7516d2a882db1abb5a8b && \
  cmake \
    -B build \
    -G Ninja \
    -DBUILD_SHARED_LIBS=OFF \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_CXX_STANDARD=20 \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DBOOST_ROOT=/boost/lib/cmake \
    -Ddeprecated-functions=OFF \
    $LIBBT_CMAKE_FLAGS && \
  cmake --build build -j $(nproc) && \
  cmake --install build

# build qbittorrent
RUN cd / && \
  wget "https://github.com/qbittorrent/qBittorrent/archive/refs/tags/release-${QBT_VERSION}.tar.gz" && \
  tar -xf "release-${QBT_VERSION}.tar.gz" && \
  cd "qBittorrent-release-${QBT_VERSION}" && \
  cmake \
    -B build \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DCMAKE_INSTALL_PREFIX=/usr \
    -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON \
    -DBOOST_ROOT=/boost/lib/cmake \
    -DGUI=OFF && \
  cmake --build build -j $(nproc) && \
  cmake --install build

# record compile-time Software Bill of Materials (sbom)
RUN cd / && \
  printf "Software Bill of Materials for building qbittorrent-nox\n\n" >> /sbom.txt && \
  echo "boost $BOOST_VERSION_MAJOR.$BOOST_VERSION_MINOR.$BOOST_VERSION_PATCH" >> /sbom.txt && \
  cd libtorrent && \
  echo "libtorrent-rasterbar git $(git rev-parse HEAD)" >> /sbom.txt && \
  cd .. && \
  echo "qBittorrent ${QBT_VERSION}" >> /sbom.txt ; \
  echo >> /sbom.txt && \
  apk list -I | sort >> /sbom.txt && \
  cat /sbom.txt

RUN cd / && \
  rm -rf boost && \
  rm -rf ./libtorrent && \
  rm -rf "qBittorrent-release-${QBT_VERSION}"

RUN apk --no-cache --purge del \
  cmake \
  git \
  g++ \
  make \
  ninja \
  openssl-dev \
  qt6-qtbase-dev \
  qt6-qtbase-private-dev \
  qt6-qttools-dev \
  zlib-dev

# image for running
FROM base

COPY --from=builder /usr/bin/qbittorrent-nox /usr/bin/qbittorrent-nox

COPY --from=builder /sbom.txt /sbom.txt

COPY docker/qbittorrent/entrypoint.sh /entrypoint.sh
COPY docker/qbittorrent/qBittorrent.conf /qBittorrent.conf

RUN chmod a+rx /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

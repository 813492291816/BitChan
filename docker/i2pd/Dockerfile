FROM alpine:3.22.1

ARG GIT_BRANCH="master"
ENV GIT_BRANCH=${GIT_BRANCH}
ARG GIT_TAG="tags/2.58.0"
ENV GIT_TAG=${GIT_TAG}
ARG GIT_COMMIT="e8d59c83754a0809b753ea7f59021160f755abad"
ENV GIT_COMMIT=${GIT_COMMIT}
ARG REPO_URL="https://github.com/PurpleI2P/i2pd.git"
ENV REPO_URL=${REPO_URL}

ENV I2PD_HOME="/home/i2pd"
ENV DATA_DIR="${I2PD_HOME}/data"

RUN mkdir -p "$I2PD_HOME" \
    && mkdir -p "$I2PD_HOME/data" \
    && adduser -S -h "$I2PD_HOME" i2pd

RUN apk update \
    && apk --no-cache --virtual build-dependendencies add make gcc g++ libtool zlib-dev boost-dev build-base openssl-dev openssl miniupnpc-dev git \
    && mkdir -p /tmp/build \
    && cd /tmp/build && git clone --progress --verbose -b ${GIT_BRANCH} ${REPO_URL} \
    && cd i2pd \
    && git checkout ${GIT_TAG} \
    && make -j$(nproc) USE_UPNP=yes \
    && cp -R contrib/certificates /i2pd_certificates \
    && mkdir -p /usr/local/bin \
    && mv i2pd /usr/local/bin \
    && cd /usr/local/bin \
    && strip i2pd \
    && rm -fr /tmp/build \
    && apk --no-cache --purge del build-dependendencies

RUN apk --no-cache add boost-filesystem boost-system boost-program_options boost-date_time boost-thread boost-iostreams openssl miniupnpc musl-utils libstdc++

COPY docker/i2pd/i2pd.conf /home/i2pd/i2pd.conf

# Set up the HTTP tunnel
#COPY docker/i2pd/tunnels.conf /home/i2pd/data/tunnels.conf

# If you have a key for a tunnel, copy it to docker/i2pd/bitchan-tunnel.dat
# before building and uncomment the lines above and below.
# If you don't have have a key file, one will be generated
#COPY docker/i2pd/bitchan-tunnel.dat /home/i2pd/data/bitchan-tunnel.dat

COPY docker/i2pd/entrypoint.sh /home/i2pd/entrypoint.sh
RUN chmod a+x /home/i2pd/entrypoint.sh

RUN echo "export DATA_DIR=${DATA_DIR}" >> /etc/profile

EXPOSE 7070 4444 4447 7656 2827 7654 7650

ENTRYPOINT [ "/home/i2pd/entrypoint.sh" ]

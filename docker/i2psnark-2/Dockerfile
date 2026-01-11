FROM alpine:3.19.1

# v2.6.1
ARG I2P_COMMIT="20df8779bdda323a244343566f5824148c33b391"
ENV I2P_COMMIT=${I2P_COMMIT}

RUN apk --no-cache add git gettext apache-ant openjdk17 zip

RUN git clone --progress --verbose https://github.com/i2p/i2p.i2p ~/i2p

RUN cd ~/i2p \
    && if [ -n "${I2P_COMMIT}" ]; then git checkout ${I2P_COMMIT}; fi \
    && ant preppkg-linux-only \
    && ant i2psnark \
    && mkdir -p /i2psnark/i2psnark.config.d \
    && unzip -d /i2psnark ~/i2p/apps/i2psnark/java/i2psnark-standalone.zip

ARG I2PSNARK_COMMIT="d5c4aacd211e712fff590685e102dd2c2c4c4dee"
ENV I2PSNARK_COMMIT=${I2PSNARK_COMMIT}

RUN git clone --progress --verbose https://github.com/i2p/i2p.plugins.i2psnark-rpc ~/i2p.plugins.i2psnark-rpc

RUN cd ~/i2p.plugins.i2psnark-rpc \
    && if [ -n "${I2PSNARK_COMMIT}" ]; then git checkout ${I2PSNARK_COMMIT}; fi \
    && cp scripts/plugin.config plugin/plugin.config \
    && ./scripts/makeplugin.sh

# allowed hostnames for web ui
ARG HOSTNAMES=""
ENV HOSTNAMES=${HOSTNAMES}

# GID on the HOST from which i2psnark will work
ARG HOST_GID=1000
ENV HOST_GID=${HOST_GID}

# UID on the HOST from which i2psnark will work
ARG HOST_UID=1000
ENV HOST_UID=${HOST_UID}

# I2CP hostname
ARG I2CP_HOST=""
ENV I2CP_HOST=${I2CP_HOST}

# I2CP port
ARG I2CP_PORT=7654
ENV I2CP_PORT=${I2CP_PORT}

RUN addgroup -g ${HOST_GID} i2psnark \
    && adduser -h /i2psnark -G i2psnark -u ${HOST_UID} -D i2psnark

RUN sed -i 's/<Set name="host">127.0.0.1<\/Set>/<Set name="host">0.0.0.0<\/Set>/' /i2psnark/i2psnark/jetty-i2psnark.xml \
    && echo "i2psnark.dir=/i2psnark/downloads" > /i2psnark/i2psnark.config.default \
    && echo "i2psnark.i2cpHost=${I2CP_HOST}" >> /i2psnark/i2psnark.config.default \
    && echo "i2psnark.i2cpPort=${I2CP_PORT}" >> /i2psnark/i2psnark.config.default \
    && echo "i2psnark.allowedHosts=${HOSTNAMES}" >> /i2psnark/i2psnark/i2psnark-appctx.config \
    && chown -R i2psnark:i2psnark /i2psnark \
    && apk --no-cache add openjdk8-jre-base su-exec shadow

VOLUME /i2psnark/i2psnark.config.d
VOLUME /i2psnark/downloads

COPY docker/i2psnark-2/entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

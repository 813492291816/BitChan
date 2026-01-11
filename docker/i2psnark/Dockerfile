FROM alpine:3.19.1

WORKDIR /

# IP to host i2psnark
ARG HOST_IP="0.0.0.0"
ENV HOST_IP=${HOST_IP}

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

RUN wget "https://i2pplus.github.io/installers/i2psnark-standalone.zip" \
    && unzip i2psnark-standalone.zip \
    && rm -rf i2psnark-standalone.zip \
    && mkdir -p /i2psnark/i2psnark.config.d \
    && sed -i "s|127.0.0.1|$HOST_IP|g" /i2psnark/jetty-i2psnark.xml \
    && echo "i2psnark.dir=/i2psnark/downloads" > /i2psnark/i2psnark.config.default \
    && echo "i2psnark.i2cpHost=${I2CP_HOST}" >> /i2psnark/i2psnark.config.default \
    && echo "i2psnark.i2cpPort=${I2CP_PORT}" >> /i2psnark/i2psnark.config.default \
    #&& echo "i2psnark.allowedHosts=${HOSTNAMES}" >> /i2psnark/i2psnark-appctx.config \
    && chown -R i2psnark:i2psnark /i2psnark \
    && apk --no-cache add openjdk8-jre-base su-exec shadow

VOLUME /i2psnark/i2psnark.config.d
VOLUME /i2psnark/downloads

COPY docker/i2psnark/entrypoint.sh /entrypoint.sh
RUN chmod a+x /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

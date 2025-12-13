FROM python:3.11-alpine

ENV MINODE_HOME="/home/minode"
ENV DATA_DIR="${MINODE_HOME}/minode_data"
ARG GIT_BRANCH="v0.3"
ENV GIT_BRANCH=${GIT_BRANCH}
ARG GIT_COMMIT="82d5deec57c8b07ee056df2d27a79236fdce054c"
ENV GIT_COMMIT=${GIT_COMMIT}
ARG REPO_URL="https://git.bitmessage.org/Bitmessage/MiNode.git"
ENV REPO_URL=${REPO_URL}

RUN mkdir -p "$MINODE_HOME" \
    && mkdir -p "$MINODE_HOME/minode_data" \
    && adduser -S -h "$MINODE_HOME" minode

RUN apk update \
    && apk --no-cache --virtual build-dependendencies add git \
    && git clone --progress --verbose -b ${GIT_BRANCH} ${REPO_URL} /tmp/minode \
    && cd /tmp/minode \
    && git checkout ${GIT_COMMIT} \
    && mv /tmp/minode/* /home/minode/ \
    && apk --no-cache --purge del build-dependendencies

# Current
# 0.3.3 82d5deec57c8b07ee056df2d27a79236fdce054c fixed i2p host issue

# Old
# 0.3.3-localfix
#COPY docker/minode/minode-Local_i2p_host_fix /home/minode/minode

# 0.3.3 (pull request exists, but needs i2p host fix) https://git.bitmessage.org/Bitmessage/MiNode/src/commit/a2bf898bca63e380435ad30e5e76fa4409e298cb
# 0.3.3 (needs i2p host fix) https://git.bitmessage.org/Bitmessage/MiNode/src/commit/efc4be0ec126fb3870139c39d39993270d4796b0

COPY docker/minode/entrypoint.sh /home/minode/entrypoint.sh

ENTRYPOINT [ "/home/minode/entrypoint.sh" ]

FROM python:3.11-alpine

ENV MINODE_HOME="/home/minode"
ENV DATA_DIR="${MINODE_HOME}/minode_data"

RUN mkdir -p "$MINODE_HOME" \
    && mkdir -p "$MINODE_HOME/minode_data" \
    && adduser -S -h "$MINODE_HOME" minode

# Current
# 0.3.5 (pull request exists, but needs i2p host fix) https://git.bitmessage.org/Bitmessage/MiNode/src/commit/a2bf898bca63e380435ad30e5e76fa4409e298cb

# Old
# 0.3.3 (needs i2p host fix) https://git.bitmessage.org/Bitmessage/MiNode/src/commit/efc4be0ec126fb3870139c39d39993270d4796b0

COPY docker/minode/minode /home/minode/minode
COPY docker/minode/entrypoint.sh /home/minode/entrypoint.sh

ENTRYPOINT [ "/home/minode/entrypoint.sh" ]

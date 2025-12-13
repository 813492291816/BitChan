FROM ibm-semeru-runtimes:open-11-jre-focal

RUN mkdir -p "/root/BiglyBT Downloads"

WORKDIR /app
RUN curl -L https://files.biglybt.com/installer/BiglyBT_unix.tar.gz -s -o - | \
    tar -xzvf - --no-same-permissions \
    biglybt/BiglyBT.jar \
    biglybt/commons-cli.jar \
    biglybt/plugins/azupdater/ \
    biglybt/plugins/azutp/ \
    biglybt/plugins/mlDHT/ \
    -C /app

COPY docker/biglybt/entrypoint.sh /entrypoint.sh

RUN chmod a+rx /entrypoint.sh

ENTRYPOINT [ "/entrypoint.sh" ]

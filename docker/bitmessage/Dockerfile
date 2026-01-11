FROM python:2.7-alpine

# Bitmessage environment varaibles
ENV BITMESSAGE_HOME="/usr/local/bitmessage" \
    VER="0.6.3.2" \
    DOCKER="TRUE" \
    HOME="/home/bitchan"

WORKDIR ${HOME}

RUN mkdir -p "$HOME" \
    && adduser -S -h "$HOME" bitchan

RUN python2 -m pip install virtualenv
RUN python2 -m virtualenv /home/bitchan/env2

COPY ./install_files/bitmessage/requirements-freeze-hashes.txt /home/bitchan/requirements_bitmessage.txt
COPY ./docker/bitmessage/bitmessage_clone.sh /home/bitchan/bitmessage_clone.sh

RUN apk update \
    && apk --no-cache add bash openssl-dev \
    && apk --no-cache --virtual build-dependendencies add build-base git libcap-dev

RUN /home/bitchan/env2/bin/python2 -m pip install --require-hashes --no-deps --no-cache-dir -r /home/bitchan/requirements_bitmessage.txt \
    && /bin/bash /home/bitchan/bitmessage_clone.sh \
    && cd /home/bitchan/PyBitmessage \
    && /home/bitchan/env2/bin/python2 setup.py install \
    && rm -f /home/bitchan/requirements_bitmessage.txt \
    && rm -f /home/bitchan/bitmessage_clone.sh

RUN apk --no-cache --purge del build-dependendencies

COPY ./docker/bitmessage/bitmessage_setup.sh /home/bitchan/bitmessage_setup.sh

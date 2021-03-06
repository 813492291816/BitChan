FROM debian:buster-slim

# Bitmessage environment varaibles
ENV BITMESSAGE_HOME /usr/local/bitmessage
ENV VER 0.6.3.2

# Bitchan environment variables
ENV DOCKER TRUE
ENV HOME /home/bitchan

ENV DEBIAN_FRONTEND noninteractive

WORKDIR ${HOME}

RUN useradd bitchan
RUN chown -R bitchan /home/bitchan

RUN mkdir -p /usr/local/bitmessage
RUN mkdir -p /usr/local/bitchan
RUN mkdir -p /usr/local/bitchan/log
RUN mkdir -p /usr/local/bitchan/downloaded_files

RUN chown -R bitchan /usr/local/bitchan
RUN chown -R bitchan /usr/local/bitmessage

# BitChan apt dependencies
RUN apt-get update && apt-get install -yq --no-install-suggests --no-install-recommends \
    curl secure-delete gnupg2 build-essential ffmpeg libsm6 libxext6 docker.io \
    python3-dev python3-setuptools python3-distutils python3-pip netbase libjpeg-dev zlib1g-dev

# Bitmessage apt dependencies
RUN apt-get install -yq --no-install-suggests --no-install-recommends \
    python-msgpack dh-python python-all-dev build-essential libssl-dev \
    python-stdeb fakeroot python-pip libcap-dev nano sed git

# Delete cached files
RUN apt-get clean
RUN rm -rf /var/lib/apt/lists/*

RUN pip2 install --upgrade pip
RUN pip3 install --upgrade pip

# Run Bitmessage clone script (gets bitmessage)
COPY ./docker/bitmessage_clone.sh ./bitmessage_clone.sh
RUN /home/bitchan/bitmessage_clone.sh
RUN rm -f /home/bitchan/bitmessage_clone.sh

# Get Bitmessage pip dependencies and install
RUN pip2 install -r /home/bitchan/PyBitmessage/requirements.txt
RUN cd /home/bitchan/PyBitmessage && python2 setup.py install

# Run Bitmessage setup script (generates initial keys.dat)
COPY ./docker/bitmessage_setup.sh ./bitmessage_setup.sh
RUN /home/bitchan/bitmessage_setup.sh
RUN rm -f /home/bitchan/bitmessage_setup.sh

# BitChan pip dependencies
COPY ./requirements.txt /home/bitchan/requirements-bitchan.txt
RUN pip3 install -r /home/bitchan/requirements-bitchan.txt
RUN rm -f /home/bitchan/requirements-bitchan.txt

RUN cd ${HOME}

# Install BitChan
USER bitchan
COPY . /home/bitchan/

USER root
RUN chown -R bitchan /usr/local/bitchan
RUN chown -R bitchan /usr/local/bitmessage

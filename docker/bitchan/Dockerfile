FROM debian:trixie-slim

# Bitchan environment variables
ENV DOCKER TRUE
ENV HOME /home/bitchan

ENV DEBIAN_FRONTEND noninteractive

WORKDIR ${HOME}

RUN useradd bitchan

RUN mkdir -p /usr/local/gnupg
RUN mkdir -p /usr/local/bitchan
RUN mkdir -p /usr/local/bitchan/log
RUN mkdir -p /usr/local/bitchan/downloaded_files
RUN chown bitchan /home/bitchan
RUN chown bitchan /usr/local/gnupg

# Apt dependencies
COPY ./docker/bitchan/install_packages_bitchan.sh /home/bitchan/install_packages_bitchan.sh
RUN /bin/bash /home/bitchan/install_packages_bitchan.sh
RUN rm -f /home/bitchan/install_packages_bitchan.txt

# BitChan pip dependencies
RUN python3 -m venv /home/bitchan/env3
COPY ./install_files/bitchan/requirements-freeze-hashes.txt /home/bitchan/requirements_bitchan_copy.txt
RUN /home/bitchan/env3/bin/python3 -m pip install --require-hashes --no-deps --no-cache-dir -r /home/bitchan/requirements_bitchan_copy.txt
RUN rm -f /home/bitchan/requirements_bitchan_copy.txt

# Install BitChan
RUN cd ${HOME}
COPY . /home/bitchan/
RUN chown -R bitchan /usr/local/bitchan

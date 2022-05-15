#!/bin/bash

LOC=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd -P )

# building Pillow 8.0.1 from source requires libjpeg-dev zlib1g-dev
sudo apt install -y python3 python3-dev python3-pip libjpeg-dev zlib1g-dev libcurl4-openssl-dev libssl-dev

printf "\nDoes Python3 venv exist?"
if [[ ! -e "$LOC"/env/bin/python3 ]]; then
    printf " No. Making.\n"
    sudo python3 -m pip install virtualenv --upgrade
    rm -rf "$LOC"/env
    python3 -m virtualenv "$LOC/env"
else
    printf " Yes. Not making.\n"
fi

"$LOC"/env/bin/pip3 install -r "$LOC"/requirements.txt

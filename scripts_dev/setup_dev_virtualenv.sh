#!/bin/bash

LOC=$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd -P )

PYTHON_BINARY_SYS_LOC="$(python3 -c "import os; print(os.environ['_'])")"
printf "\nDoes Python3 venv exist?"
if [[ ! -e "$LOC"/env/bin/python3 ]]; then
    printf " No. Making.\n"
    pip3 install virtualenv --upgrade
    rm -rf "$LOC"/env
    virtualenv --system-site-packages -p "${PYTHON_BINARY_SYS_LOC}" "$LOC/env"
else
    printf " Yes. Not making.\n"
fi

"$LOC"/env/bin/pip3 install -r "$LOC"/requirements.txt

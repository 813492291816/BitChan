#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Stegano - Stegano is a pure Python steganography module.
# Copyright (C) 2010-2019 Cédric Bonhomme - https://www.cedricbonhomme.org
#
# For more information : https://git.sr.ht/~cedric/stegano
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>

__author__ = "Cedric Bonhomme"
__version__ = "$Revision: 0.3 $"
__date__ = "$Date: 2010/10/01 $"
__revision__ = "$Date: 2017/05/04 $"
__license__ = "GPLv3"

import base64
import itertools
from functools import reduce
from typing import IO, Iterator, List, Tuple, Union

from PIL import Image

ENCODINGS = {"UTF-8": 8, "UTF-32LE": 32}


def a2bits(chars: str) -> str:
    """Converts a string to its bits representation as a string of 0's and 1's.

    >>> a2bits("Hello World!")
    '010010000110010101101100011011000110111100100000010101110110111101110010011011000110010000100001'
    """
    return bin(reduce(lambda x, y: (x << 8) + y, (ord(c) for c in chars), 1))[3:]


def a2bits_list(chars: str, encoding: str = "UTF-8") -> List[str]:
    """Convert a string to its bits representation as a list of 0's and 1's.

    >>>  a2bits_list("Hello World!")
    ['01001000',
    '01100101',
    '01101100',
    '01101100',
    '01101111',
    '00100000',
    '01010111',
    '01101111',
    '01110010',
    '01101100',
    '01100100',
    '00100001']
    >>> "".join(a2bits_list("Hello World!"))
    '010010000110010101101100011011000110111100100000010101110110111101110010011011000110010000100001'
    """
    return [bin(ord(x))[2:].rjust(ENCODINGS[encoding], "0") for x in chars]


def bs(s: int) -> str:
    """Converts an int to its bits representation as a string of 0's and 1's.
    """
    return str(s) if s <= 1 else bs(s >> 1) + str(s & 1)


def setlsb(component: int, bit: str) -> int:
    """Set Least Significant Bit of a colour component.
    """
    return component & ~1 | int(bit)


def n_at_a_time(
    items: List[int], n: int, fillvalue: str
) -> Iterator[Tuple[Union[int, str]]]:
    """Returns an iterator which groups n items at a time.
    Any final partial tuple will be padded with the fillvalue

    >>> list(n_at_a_time([1, 2, 3, 4, 5], 2, 'X'))
    [(1, 2), (3, 4), (5, 'X')]
    """
    it = iter(items)
    return itertools.zip_longest(*[it] * n, fillvalue=fillvalue)


def binary2base64(binary_file: str) -> str:
    """Convert a binary file (OGG, executable, etc.) to a
    printable string.
    """
    # Use mode = "rb" to read binary file
    with open(binary_file, "rb") as bin_file:
        encoded_string = base64.b64encode(bin_file.read())
    return encoded_string.decode()


def base642binary(b64_fname: str) -> bytes:
    """Convert a printable string to a binary file.
    """
    b64_fname += "==="
    return base64.b64decode(b64_fname)


def open_image(fname_or_instance: Union[str, IO[bytes]]):
    """Opens a Image and returns it.

    :param fname_or_instance: Can either be the location of the image as a
                              string or the Image.Image instance itself.
    """
    if isinstance(fname_or_instance, Image.Image):
        return fname_or_instance

    return Image.open(fname_or_instance)

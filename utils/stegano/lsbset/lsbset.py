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
__version__ = "$Revision: 0.7 $"
__date__ = "$Date: 2016/03/13 $"
__revision__ = "$Date: 2019/05/31 $"
__license__ = "GPLv3"

from typing import IO, Iterator, Union

from PIL import Image

from utils.stegano import tools


def hide(
    input_image: Union[str, IO[bytes]],
    message: str,
    generator: Iterator[int],
    shift: int = 0,
    encoding: str = "UTF-8",
    auto_convert_rgb: bool = False,
):
    """Hide a message (string) in an image with the
    LSB (Least Significant Bit) technique.
    """
    message_length = len(message)
    assert message_length != 0, "message length is zero"

    img = tools.open_image(input_image)

    if img.mode not in ["RGB", "RGBA"]:
        if not auto_convert_rgb:
            print("The mode of the image is not RGB. Mode is {}".format(img.mode))
            answer = input("Convert the image to RGB ? [Y / n]\n") or "Y"
            if answer.lower() == "n":
                raise Exception("Not a RGB image.")
        img = img.convert("RGB")

    img_list = list(img.getdata())
    width, height = img.size
    index = 0

    message = str(message_length) + ":" + str(message)
    message_bits = "".join(tools.a2bits_list(message, encoding))
    message_bits += "0" * ((3 - (len(message_bits) % 3)) % 3)

    npixels = width * height
    len_message_bits = len(message_bits)
    if len_message_bits > npixels * 3:
        raise Exception(
            "The message you want to hide is too long: {}".format(message_length)
        )
    while shift != 0:
        next(generator)
        shift -= 1

    while index + 3 <= len_message_bits:
        generated_number = next(generator)
        r, g, b, *a = img_list[generated_number]

        # Change the Least Significant Bit of each colour component.
        r = tools.setlsb(r, message_bits[index])
        g = tools.setlsb(g, message_bits[index + 1])
        b = tools.setlsb(b, message_bits[index + 2])

        # Save the new pixel
        if img.mode == "RGBA":
            img_list[generated_number] = (r, g, b, *a)
        else:
            img_list[generated_number] = (r, g, b)

        index += 3

    # create empty new image of appropriate format
    encoded = Image.new(img.mode, (img.size))

    # insert saved data into the image
    encoded.putdata(img_list)

    return encoded


def reveal(
    input_image: Union[str, IO[bytes]],
    generator: Iterator[int],
    shift: int = 0,
    encoding: str = "UTF-8",
):
    """Find a message in an image (with the LSB technique).
    """
    img = tools.open_image(input_image)
    img_list = list(img.getdata())
    width, height = img.size
    buff, count = 0, 0
    bitab = []
    limit = None

    while shift != 0:
        next(generator)
        shift -= 1

    while True:
        generated_number = next(generator)
        # color = [r, g, b]
        for color in img_list[generated_number][:3]:  # ignore the alpha
            buff += (color & 1) << (tools.ENCODINGS[encoding] - 1 - count)
            count += 1
            if count == tools.ENCODINGS[encoding]:
                bitab.append(chr(buff))
                buff, count = 0, 0
                if bitab[-1] == ":" and limit == None:
                    if "".join(bitab[:-1]).isdigit():
                        limit = int("".join(bitab[:-1]))
                    else:
                        raise IndexError("Impossible to detect message.")
        if len(bitab) - len(str(limit)) - 1 == limit:
            return "".join(bitab)[len(str(limit)) + 1 :]

import logging
import multiprocessing
import os
from io import BytesIO

import gnupg

from utils.files import delete_file
from utils.general import get_random_alphanumeric_string

logger = logging.getLogger('bitchan.encryption_decrypt')


def decrypt_safe_size(message, passphrase, max_size):
    """
    Ensure a decrypted message is of a safe size.
    Since incredibly large PGP messages (e.g. several GB of a repeating character) can
    be encrypted to a very small message, we must monitor the size of the decrypted
    data, and if it grows beyond a size threshold, halt the decryption process.
    """
    gpg = gnupg.GPG()
    tmp_decrypted = "/tmp/decrypted_msg_{}".format(
        get_random_alphanumeric_string(
            16, with_punctuation=False, with_spaces=False))

    delete_file(tmp_decrypted)

    def decrypt_message(msg):
        gpg.decrypt_file(msg, passphrase=passphrase, output=tmp_decrypted)

    process = multiprocessing.Process(
        target=decrypt_message, args=(BytesIO(message.encode()),))
    process.start()

    size_too_large = False
    while process.is_alive():
        if not os.path.exists(tmp_decrypted):
            pass
        else:
            if os.path.getsize(tmp_decrypted) > max_size:
                process.terminate()
                size_too_large = True
    try:
        if os.path.exists(tmp_decrypted) and not size_too_large:
            with open(tmp_decrypted, 'r') as file:
                decrypted_str = file.read()
            return decrypted_str
        else:
            return None
    finally:
        delete_file(tmp_decrypted)

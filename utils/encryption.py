import logging
import multiprocessing
import os
from io import BytesIO

import gnupg
from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

from utils.files import delete_file
from utils.general import get_random_alphanumeric_string

logger = logging.getLogger('bitchan.encryption')


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

    def decrypt_message(message):
        gpg.decrypt_file(message, passphrase=passphrase, output=tmp_decrypted)

    proc = multiprocessing.Process(
        target=decrypt_message, args=(BytesIO(message.encode()),))
    proc.start()

    size_too_large = False
    while proc.is_alive():
        if not os.path.exists(tmp_decrypted):
            pass
        else:
            if os.path.getsize(tmp_decrypted) > max_size:
                proc.terminate()
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


def crypto_multi_enc(cipher_str, password, path_file_in, path_file_out, key_bytes=32):
    buffer_size = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once

    file_in = open(path_file_in, 'rb')
    file_out = open(path_file_out, 'wb')

    salt = get_random_bytes(32)  # 32-bit salt
    key = scrypt(password, salt, key_len=key_bytes, N=2 ** 20, r=8, p=1)  # Generate key using password and salt

    file_out.write(salt)  # Write salt to the output file

    if cipher_str == "AES-GCM":
        cipher = AES.new(key, AES.MODE_GCM)  # encrypt data
        file_out.write(cipher.nonce)  # Write nonce to the output file
    elif cipher_str == "XChaCha20-Poly1305":
        nonce = get_random_bytes(24)  # for XChaCha20-Poly1305, nonce must be 24 bytes long
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)  # encrypt data
        file_out.write(nonce)  # Write nonce to the output file
    else:
        logger.error("Unknown cipher: {}".format(cipher_str))
        return

    data = file_in.read(buffer_size)
    while len(data) != 0:  # Check if we need to encrypt anymore data
        encrypted_data = cipher.encrypt(data)  # Encrypt the data we read
        file_out.write(encrypted_data)  # Write encrypted data to the output file
        data = file_in.read(buffer_size)  # Read some more of the file

    tag = cipher.digest()  # Signal to the cipher that we are done and get the tag
    file_out.write(tag)

    file_in.close()
    file_out.close()
    return True


def crypto_multi_decrypt(cipher_str, password, path_file_in, path_file_out, key_bytes=32, max_size_bytes=None):
    buffer_size = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once

    # Open files
    file_in = open(path_file_in, 'rb')
    file_out = open(path_file_out, 'wb')

    # Read salt and generate key
    salt = file_in.read(32)  # read 32-bit salt
    key = scrypt(password, salt, key_len=key_bytes, N=2 ** 20, r=8, p=1)  # Generate key using password and salt

    if cipher_str == "AES-GCM":
        nonce_length = 16
        nonce = file_in.read(nonce_length)  # The nonce is 16 bytes long
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    elif cipher_str == "XChaCha20-Poly1305":
        nonce_length = 24
        nonce = file_in.read(nonce_length)  # The nonce is 24 bytes long
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    else:
        logger.error("Unknown cipher: {}".format(cipher_str))
        return

    # Identify how many bytes of encrypted data there is
    # We know that the salt (32) + the nonce (based on cipher) + the data (?) + the tag (16) is in the file
    # So some basic algebra can tell us how much data we need to read to decrypt
    file_in_size = os.path.getsize(path_file_in)
    encrypted_data_size = file_in_size - 32 - nonce_length - 16  # Total - salt - nonce - tag = encrypted data

    # Read, decrypt and write the data
    file_size = 0
    for _ in range(int(encrypted_data_size / buffer_size)):  # Identify how many loops of full buffer reads needed
        data = file_in.read(buffer_size)  # Read data from the encrypted file
        decrypted_data = cipher.decrypt(data)  # Decrypt the data
        file_out.write(decrypted_data)  # Write decrypted data to the output file
        file_size += len(decrypted_data)
        logger.info("Decrypted size (so far): {} bytes".format(file_size))

        if max_size_bytes and file_size > max_size_bytes:
            logger.error(
                "Extracted file is larger than max allowed ({} bytes > {} bytes). "
                "Cancelling/deleting.".format(
                    file_size, max_size_bytes))
            file_in.close()
            file_out.close()
            os.remove(path_file_out)
            return False

    data = file_in.read(int(encrypted_data_size % buffer_size))  # Read what calculated to be left of encrypted data
    decrypted_data = cipher.decrypt(data)  # Decrypt data
    file_out.write(decrypted_data)  # Write decrypted data to the output file
    file_size += len(decrypted_data)
    logger.info("Decrypted size (final): {} bytes".format(file_size))

    if max_size_bytes and file_size > max_size_bytes:
        logger.error(
            "Extracted file is larger than max allowed ({} bytes > {} bytes). "
            "Cancelling/deleting.".format(
                file_size, max_size_bytes))
        file_in.close()
        file_out.close()
        os.remove(path_file_out)
        return False

    # Verify encrypted file was not tampered with
    tag = file_in.read(16)
    try:
        cipher.verify(tag)
    except ValueError as e:
        # If we get a ValueError, there was an error when decrypting so delete the file we created
        file_in.close()
        file_out.close()
        os.remove(path_file_out)
        raise e

    file_in.close()
    file_out.close()
    return True

import logging
import os
from queue import Queue, Empty
from resource import getrusage, RUSAGE_SELF
from threading import Thread

from Crypto.Cipher import AES
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes

from utils.files import LF
from utils.files import human_readable_size

logger = logging.getLogger('bitchan.encryption')


def memory_monitor(command_queue: Queue, poll_interval=1):
    max_rss = 0
    old_max = 0
    while True:
        try:
            command_queue.get(timeout=poll_interval)
            logger.info(f"(END) Max RSS {max_rss} KB")
            return
        except Empty:
            max_rss = getrusage(RUSAGE_SELF).ru_maxrss
            if max_rss > old_max:
                old_max = max_rss
                logger.info(f"Max RSS {max_rss} KB")


def crypto_multi_enc(cipher_str, password, path_file_in, path_file_out, key_bytes=32):
    buffer_size = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once

    file_in = open(path_file_in, 'rb')
    file_out = open(path_file_out, 'wb')

    salt = get_random_bytes(32)  # 32-byte salt

    queue = Queue()
    poll_interval = 0.5
    monitor_thread = Thread(target=memory_monitor, args=(queue, poll_interval))
    monitor_thread.start()

    l_file = "/var/lock/key_scrypt.lock"
    lf = LF()
    if lf.lock_acquire(l_file, to=60):
        try:
            key = scrypt(password, salt, key_len=key_bytes, N=2 ** 20, r=8, p=1)  # Generate key using password and salt
        except Exception as err:
            logger.error("Error scrypt(): {}".format(err))
            return
        finally:
            lf.lock_release(l_file)
    else:
        logger.error(f"Could not acquire lock {l_file}")
        return

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

    queue.put('stop')
    monitor_thread.join()

    return True


def crypto_multi_decrypt(cipher_str, password, path_file_in, path_file_out,
                         key_bytes=32, max_size_bytes=None, skip_size_check=False):
    buffer_size = 1024 * 1024  # The size in bytes that we read, encrypt and write to at once

    # Open files
    file_in = open(path_file_in, 'rb')
    file_out = open(path_file_out, 'wb')

    # Read salt and generate key
    salt = file_in.read(32)  # read 32-byte salt

    l_file = "/var/lock/key_scrypt.lock"
    lf = LF()
    if lf.lock_acquire(l_file, to=60):
        try:
            key = scrypt(password, salt, key_len=key_bytes, N=2 ** 20, r=8, p=1)  # Generate key using password and salt
        except Exception as err:
            logger.error("Error scrypt(): {}".format(err))
            return
        finally:
            lf.lock_release(l_file)
    else:
        logger.error("Unknown cipher: {}".format(cipher_str))
        return

    if cipher_str == "AES-GCM":
        nonce_length = 16
        nonce = file_in.read(nonce_length)  # The nonce is 16 bytes long
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    elif cipher_str == "XChaCha20-Poly1305":
        nonce_length = 24
        nonce = file_in.read(nonce_length)  # The nonce is 24 bytes long
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    else:
        err = "Unknown cipher: {}".format(cipher_str)
        logger.error(err)
        return False, err

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

        if not skip_size_check and max_size_bytes and file_size > max_size_bytes:
            err = f"During decryption, max attachment size exceeded ({human_readable_size(max_size_bytes)})."
            logger.error(err)
            file_in.close()
            file_out.close()
            os.remove(path_file_out)
            return False, err

    data = file_in.read(int(encrypted_data_size % buffer_size))  # Read what calculated to be left of encrypted data
    decrypted_data = cipher.decrypt(data)  # Decrypt data
    file_out.write(decrypted_data)  # Write decrypted data to the output file
    file_size += len(decrypted_data)
    logger.info("Decrypted size (final): {} bytes".format(file_size))

    if not skip_size_check and max_size_bytes and file_size > max_size_bytes:
        err = "During decryption, max attachment size exceeded ({} > {}).".format(
            human_readable_size(file_size), human_readable_size(max_size_bytes))
        logger.error(err)
        file_in.close()
        file_out.close()
        os.remove(path_file_out)
        return False, err

    # Verify encrypted file was not tampered with
    tag = file_in.read(16)
    try:
        cipher.verify(tag)
    except ValueError as e:
        # If we get a ValueError, there was an error when decrypting so delete the file we created
        file_in.close()
        file_out.close()
        os.remove(path_file_out)
        err = f"Error decrypting: {e}"
        return False, err

    file_in.close()
    file_out.close()
    return True, "Success"

import hashlib
import logging
import os.path
import shutil
import time
from pathlib import Path
from threading import Thread

import bs4
import cv2
import requests
from PIL import Image
from PIL import UnidentifiedImageError
from user_agent import generate_user_agent

import config
from database.models import Chan
from database.models import Messages
from database.utils import session_scope
from utils.encryption import crypto_multi_decrypt
from utils.files import data_file_multiple_insert
from utils.files import delete_file
from utils.files import generate_thumbnail
from utils.files import human_readable_size
from utils.general import get_random_alphanumeric_string
from utils.steg import check_steg

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.utils.download')


def generate_hash(file_path):
    """
    Generates an SHA256 hash value from a file

    :param file_path: path to the file for hash validation
    :type file_path: string
    """
    m = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(1000 * 1000)  # 1MB
            if not chunk:
                break
            m.update(chunk)
    return m.hexdigest()


def validate_file(file_path, hash):
    """
    Validates a file against an SHA256 hash value

    :param file_path: path to the file for hash validation
    :type file_path:  string
    :param hash:      expected hash value of the file
    :type hash:       string -- SHA256 hash value
    """
    m = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(1000 * 1000)  # 1MB
            if not chunk:
                break
            m.update(chunk)
    return m.hexdigest() == hash


def report_downloaded_amount(message_id, download_path, file_size):
    try:
        with session_scope(DB_PATH) as new_session:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message:
                timer = time.time()
                while os.path.exists(download_path):
                    if timer < time.time():
                        while timer < time.time():
                            timer += 3
                        downloaded_size = os.path.getsize(download_path)
                        message.file_progress = "{} downloaded ({:.1f} %)".format(
                            human_readable_size(downloaded_size),
                            (downloaded_size / file_size) * 100)
                        new_session.commit()
                    time.sleep(1)
    except:
        logger.error("Exception while reporting file size")


def download_with_resume(message_id, url, file_path, hash=None, timeout=15):
    """
    Performs a HTTP(S) download that can be restarted if prematurely terminated.
    The HTTP server must support byte ranges.
    From https://gist.github.com/idolpx/921fc79368903d3a90800ef979abb787
    """
    # don't download if the file exists
    if os.path.exists(file_path):
        return
    first_byte = 0
    block_size = 1000 * 500  # 0.5MB
    tmp_file_path = "{}.part".format(file_path)
    if os.path.exists(tmp_file_path):
        first_byte = os.path.getsize(tmp_file_path)
    file_mode = 'ab' if first_byte else 'wb'
    if first_byte:
        logger.info('Resuming download from {:.1f} MB'.format(first_byte / 1e6))
    else:
        logger.info('Starting download')
    file_size = -1
    try:
        file_size = int(requests.head(
            url,
            headers={'User-Agent': generate_user_agent()}).headers['Content-length'])
        logger.debug('File size is {}'.format(file_size))

        if not os.path.exists(tmp_file_path):
            Path(tmp_file_path).touch()
        thread_download = Thread(
            target=report_downloaded_amount, args=(message_id, tmp_file_path, file_size,))
        thread_download.daemon = True
        thread_download.start()

        headers = {
            "Range": "bytes={}-".format(first_byte),
            'User-Agent': generate_user_agent()
        }
        r = requests.get(
            url,
            proxies=config.TOR_PROXIES,
            headers=headers,
            stream=True,
            timeout=timeout)
        with open(tmp_file_path, file_mode) as f:
            for chunk in r.iter_content(chunk_size=block_size):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
    except IOError as e:
        logger.error('IO Error: {}'.format(e))
    finally:
        # rename the temp download file to the correct name if fully downloaded
        if file_size == os.path.getsize(tmp_file_path):
            # if there's a hash value, validate the file
            if hash and not validate_file(tmp_file_path, hash):
                raise Exception('Error validating the file against its SHA256 hash')
            shutil.move(tmp_file_path, file_path)
            return file_path
        elif file_size == -1:
            logger.error('Error getting Content-Length from server: {}'.format(url))


def download_and_extract(
        address,
        message_id,
        file_url,
        file_extracts_start_base64,
        upload_filename,
        file_path,
        file_extension,
        file_sha256_hash,
        file_enc_cipher,
        file_enc_key_bytes,
        file_enc_password,
        img_thumb_filename):

    logger.info("download_and_extract({}, {}, {}, {}, {}, {}, {}, {}, {}, {}, password={}".format(
        address,
        message_id,
        file_url,
        upload_filename,
        file_path,
        file_extension,
        file_sha256_hash,
        img_thumb_filename,
        file_enc_cipher,
        file_enc_key_bytes,
        file_enc_password))

    file_sha256_hashes_match = False
    file_size = None
    file_do_not_download = None
    file_download_successful = None
    media_height = None
    media_width = None
    message_steg = None
    downloaded = None
    force_allow_download = False
    download_url = None

    # save downloaded file to /tmp/
    # filename has been randomly generated, so no risk of collisions
    download_path = "/tmp/{}".format(upload_filename)

    # Parse page for URL to direct download zip
    try:
        html_return = requests.get(
            file_url,
            headers={'User-Agent': generate_user_agent()})
        soup = bs4.BeautifulSoup(html_return.text, "html.parser")
        for link in soup.find_all('a', href=True):
            href = link.get('href')
            if href and href.endswith(upload_filename):
                download_url = href
                break
    except:
        logger.error("{}: Error getting upload page".format(message_id[0:6]))

    if not download_url:
        logger.error("{}: Could not find URL for {}".format(
            message_id[0:6], upload_filename))
    else:
        logger.info("{}: Found URL, checking size".format(message_id[0:6]))
        for _ in range(3):
            from bitchan_flask import nexus
            if message_id in nexus.get_start_download():
                force_allow_download = True
                file_do_not_download = False
                nexus.remove_start_download(message_id)
            else:
                try:
                    file_size = int(requests.head(
                        download_url,
                        headers={'User-Agent': generate_user_agent()}).headers['Content-length'])
                    if file_size and file_size > config.DOWNLOAD_MAX_AUTO:
                        downloaded = "too_large"
                        file_do_not_download = True
                        logger.info(
                            "{}: File size ({}) is greater than max allowed "
                            "to auto-download ({}). Not downloading.".format(
                                message_id[0:6],
                                human_readable_size(file_size),
                                human_readable_size(config.DOWNLOAD_MAX_AUTO)))
                        break
                    else:
                        logger.info(
                            "{}: File size ({}) is less than max allowed "
                            "to auto-download ({}). Downloading.".format(
                                message_id[0:6],
                                human_readable_size(file_size),
                                human_readable_size(config.DOWNLOAD_MAX_AUTO)))
                        break
                except:
                    logger.error("{}: Could not get file size".format(message_id[0:6]))
                    file_do_not_download = True
                    break
            time.sleep(5)

        if file_do_not_download and not force_allow_download:
            return (file_download_successful,
                    file_size,
                    file_do_not_download,
                    file_sha256_hashes_match,
                    media_height,
                    media_width,
                    message_steg)
        else:
            file_do_not_download = False

        for _ in range(config.DOWNLOAD_ATTEMPTS):
            try:
                download_with_resume(message_id, download_url, download_path)
                if file_size == os.path.getsize(download_path):
                    break
            except Exception as err:
                logger.error("Exception downloading: {}".format(err))
            time.sleep(60)

        try:
            if file_size == os.path.getsize(download_path):
                logger.info("{}: Download completed".format(message_id[0:6]))
                downloaded = "downloaded"
            else:
                logger.error("Issue downloading file")
        except:
            logger.error("Issue downloading file")

        if downloaded == "too_large":
            logger.info("{}: File size ({}) is larger than allowed to auto-download ({})".format(
                message_id[0:6], file_size, human_readable_size(config.DOWNLOAD_MAX_AUTO)))
        elif downloaded == "downloaded":
            logger.info("{}: File successfully downloaded".format(message_id[0:6]))
            file_download_successful = True
        elif downloaded is None:
            logger.error("{}: Could not download zip after {} attempts".format(
                message_id[0:6], config.DOWNLOAD_ATTEMPTS))
            file_download_successful = False

        if file_download_successful:
            # Add missing parts back to file
            if file_extracts_start_base64:
                size_before = os.path.getsize(download_path)
                data_file_multiple_insert(download_path, file_extracts_start_base64, chunk=4096)
                logger.info("{}: File data insertion. Before: {}, After: {}".format(
                    message_id[0:6], size_before, os.path.getsize(download_path)))

            # compare SHA256 hashes
            if file_sha256_hash:
                if not validate_file(download_path, file_sha256_hash):
                    logger.info(
                        "{}: File SHA256 hash ({}) does not match provided SHA256"
                        " hash ({}). Deleting.".format(
                            message_id[0:6],
                            generate_hash(download_path),
                            file_sha256_hash))
                    file_sha256_hashes_match = False
                    file_download_successful = False
                    delete_file(download_path)
                    return (file_download_successful,
                            file_size,
                            file_do_not_download,
                            file_sha256_hashes_match,
                            media_height,
                            media_width,
                            message_steg)
                else:
                    file_sha256_hashes_match = True
                    logger.info("{}: File SHA256 hashes match ({})".format(
                        message_id[0:6], file_sha256_hash))

            # decrypt file
            logger.info("{}: Decrypting file".format(message_id[0:6]))
            extract_filename = "{}.{}".format(
                get_random_alphanumeric_string(12, with_punctuation=False, with_spaces=False),
                file_extension)
            extract_path = "/tmp"
            full_path_filename = os.path.join(extract_path, extract_filename)
            delete_file(full_path_filename)  # make sure no file already exists

            with session_scope(DB_PATH) as new_session:
                message = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if message:
                    message.file_progress = "Decrypting file"
                    new_session.commit()

            try:
                ret_crypto = crypto_multi_decrypt(
                    file_enc_cipher,
                    file_enc_password,
                    download_path,
                    full_path_filename,
                    key_bytes=file_enc_key_bytes)
                if not ret_crypto:
                    logger.error("{}: Issue decrypting file")

                # z = zipfile.ZipFile(download_path)
                # z.setpassword(config.PASSPHRASE_ZIP.encode())
                # z.extract(extract_filename, path=extract_path)

                shutil.copy(full_path_filename, file_path)  # Copy
                delete_file(full_path_filename)  # Secure delete
                logger.info("{}: Finished decrypting file".format(message_id[0:6]))

                # Verify image and video dimensions
                if file_extension in config.FILE_EXTENSIONS_IMAGE:
                    try:
                        with session_scope(DB_PATH) as new_session:
                            message = new_session.query(Messages).filter(
                                Messages.message_id == message_id).first()
                            if message:
                                message.file_progress = "Calculating image dimensions"
                                new_session.commit()
                        logger.info("{}: Determining image dimensions".format(message_id[0:6]))
                        Image.MAX_IMAGE_PIXELS = 500000000
                        im = Image.open(file_path)
                        media_width, media_height = im.size
                    except UnidentifiedImageError as e:
                        logger.exception("{}: Error identifying image: {}".format(message_id[0:6], e))
                    except Exception as e:
                        logger.exception("{}: Error opening/stripping image: {}".format(message_id[0:6], e))
                elif file_extension in config.FILE_EXTENSIONS_VIDEO:
                    try:
                        with session_scope(DB_PATH) as new_session:
                            message = new_session.query(Messages).filter(
                                Messages.message_id == message_id).first()
                            if message:
                                message.file_progress = "Calculating video dimensions"
                                new_session.commit()
                        logger.info("{}: Determining video dimensions".format(message_id[0:6]))
                        vid = cv2.VideoCapture(file_path)
                        media_height = vid.get(cv2.CAP_PROP_FRAME_HEIGHT)
                        media_width = vid.get(cv2.CAP_PROP_FRAME_WIDTH)
                        logger.info("{}: Video dimensions: {}x{}".format(
                            message_id[0:6], media_width, media_height))
                    except Exception as e:
                        logger.exception("{}: Error getting video dimensions: {}".format(message_id[0:6], e))

                file_size = os.path.getsize(file_path)
                if file_extension in config.FILE_EXTENSIONS_IMAGE:
                    # If image file, check for steg message
                    with session_scope(DB_PATH) as new_session:
                        pgp_passphrase_steg = config.PASSPHRASE_STEG
                        chan = new_session.query(Chan).filter(
                            Chan.address == address).first()
                        if chan and chan.pgp_passphrase_steg:
                            pgp_passphrase_steg = chan.pgp_passphrase_steg

                        message_steg = check_steg(
                            message_id,
                            file_extension,
                            passphrase=pgp_passphrase_steg,
                            file_path=file_path)

                        message = new_session.query(Messages).filter(
                            Messages.message_id == message_id).first()
                        if message:
                            message.file_progress = "generating image thumbnail"
                            new_session.commit()

                    generate_thumbnail(
                        message_id, file_path, img_thumb_filename, file_extension)

                with session_scope(DB_PATH) as new_session:
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = "file download/saving complete"
                        new_session.commit()
            except Exception:
                logger.exception("Error processing file")

        delete_file(download_path)

    return (file_download_successful,
            file_size,
            file_do_not_download,
            file_sha256_hashes_match,
            media_height,
            media_width,
            message_steg)

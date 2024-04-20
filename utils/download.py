import hashlib
import html
import json
import logging
import os
import os.path
import random
import shutil
import time
import zipfile
from pathlib import Path
from threading import Thread
from urllib.parse import urlparse

try:
    import pillow_avif  # PIL avif support/ Must come before PIL import.
except:
    pass

import bs4
import cv2
import imagehash
import qbittorrentapi
import requests
from PIL import ExifTags
from PIL import Image
from PIL import UnidentifiedImageError
from sqlalchemy import or_
from user_agent import generate_user_agent

import config
from bitchan_client import DaemonCom
from database.models import GlobalSettings
from database.models import Messages
from database.models import UploadSites
from database.models import UploadTorrents
from database.utils import session_scope
from utils.encryption import crypto_multi_decrypt
from utils.files import LF
from utils.files import count_files_in_zip
from utils.files import data_file_multiple_insert
from utils.files import delete_file
from utils.files import delete_files_recursive
from utils.files import extract_zip
from utils.files import generate_thumbnail_image
from utils.files import generate_thumbnail_video
from utils.files import human_readable_size
from utils.files import return_file_hashes
from utils.general import get_random_alphanumeric_string
from utils.i2p import get_i2p_session
from utils.posts import delete_post
from utils.posts import delete_thread
from utils.posts import file_hash_banned
from utils.shared import add_mod_log_entry
from utils.shared import regenerate_card_popup_post_html
from utils.steg import check_steg
from utils.tor import get_tor_session

logger = logging.getLogger('bitchan.download')
daemon_com = DaemonCom()


def generate_hash(file_path):
    """
    Generates an SHA256 hash value from a file

    :param file_path: path to the file for hash validation
    :type file_path: string
    """
    sha256_hash = None
    if os.path.exists(file_path):
        m = hashlib.sha256()
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(1000 * 1000)  # 1MB
                if not chunk:
                    break
                m.update(chunk)
        sha256_hash = m.hexdigest()
    return sha256_hash


def validate_file(file_path, hash_val):
    """
    Validates a file against an SHA256 hash value

    :param file_path: path to the file for hash validation
    :type file_path:  string
    :param hash_val:      expected hash value of the file
    :type hash_val:       string -- SHA256 hash value
    """
    m = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(1000 * 1000)  # 1MB
            if not chunk:
                break
            m.update(chunk)
    return m.hexdigest() == hash_val


def report_downloaded_amount(message_id, download_path, file_size):
    try:
        timer = time.time()
        while os.path.exists(download_path):
            if timer < time.time():
                while timer < time.time():
                    timer += 3
                with session_scope(config.DB_PATH) as new_session:
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        downloaded_size = os.path.getsize(download_path)
                        message.file_progress = "{} / {} downloaded ({:.1f} %)".format(
                            human_readable_size(downloaded_size),
                            human_readable_size(file_size),
                            (downloaded_size / file_size) * 100)
                        message.regenerate_post_html = True
                        new_session.commit()
                    else:
                        break
            time.sleep(1)
    except:
        logger.error("Exception while reporting file size")


def allow_download(message_id):
    """Allow a user to initiate the download of post attachments"""
    try:
        logger.info("{}: Allowing download".format(message_id[-config.ID_LENGTH:].upper()))
        with session_scope(config.DB_PATH) as new_session:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if not message:
                return

            #
            # Check if attachment is an i2p torrent
            #
            torrent = new_session.query(UploadTorrents).filter(
                UploadTorrents.message_id == message_id).first()
            if torrent:
                # Resume torrent. When download completes, it will be automatically processed by the daemon
                conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
                qbt_client = qbittorrentapi.Client(**conn_info)
                try:
                    qbt_client.auth_log_in()
                    qbt_client.torrents_resume(torrent_hashes=torrent.torrent_hash)
                    logger.info(f"Resuming torrent {torrent.torrent_hash}")
                except:
                    logger.exception(f"qBittorrent error")
                qbt_client.auth_log_out()

                message.file_do_not_download = False
                message.start_download = True
                new_session.commit()

            #
            # Attachment is not a torrent, check other methods
            #
            else:
                file_download_successful = False
                media_info = {}
                file_progress = None
                file_path = "{}/{}".format(config.FILE_DIRECTORY, message.saved_file_filename)

                # Pick a download slot to fill (2 slots per domain)
                domain = urlparse(message.file_url).netloc
                lockfile1 = "/var/lock/upload_{}_1.lock".format(domain)
                lockfile2 = "/var/lock/upload_{}_2.lock".format(domain)

                lf = LF()
                lockfile = random.choice([lockfile1, lockfile2])
                if lf.lock_acquire(lockfile, to=600):
                    try:
                        (file_download_successful,
                         file_size,
                         file_amount,
                         file_do_not_download,
                         file_sha256_hashes_match,
                         file_progress,
                         media_info,
                         message_steg) = download_and_extract(
                            message_id,
                            message.file_url,
                            json.loads(message.file_upload_settings),
                            json.loads(message.file_extracts_start_base64),
                            message.upload_filename,
                            file_path,
                            message.file_sha256_hash,
                            message.file_enc_cipher,
                            message.file_enc_key_bytes,
                            message.file_enc_password)
                    finally:
                        lf.lock_release(lockfile)

                if file_download_successful:
                    if file_size:
                        message.file_size = file_size
                    if file_amount:
                        message.file_amount = file_amount
                    message.file_download_successful = file_download_successful
                    message.file_do_not_download = file_do_not_download
                    message.file_sha256_hashes_match = file_sha256_hashes_match
                    message.media_info = json.dumps(media_info)
                    message.message_steg = json.dumps(message_steg)
                    message.file_progress = None
                    new_session.commit()
                elif file_progress:
                    message.file_progress = file_progress
                    new_session.commit()

                message.file_currently_downloading = False
                new_session.commit()

                time.sleep(20)
                regenerate_card_popup_post_html(message_id=message_id)
                check_banned_file_hashes(message_id, media_info)
    except Exception as e:
        logger.error("{}: Error allowing download: {}".format(message_id[-config.ID_LENGTH:].upper(), e))


def check_banned_file_hashes(message_id, media_info):
    """check for banned file hashes and delete post/thread if banned"""
    with session_scope(config.DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if not message or not media_info:
            return

        banned_hashes = file_hash_banned(
            return_file_hashes(media_info), address=message.thread.chan.address)
        if not banned_hashes:
            return

        logger.error(f"{message.post_id}: File hash banned. Deleting.")
        if message.is_op:
            delete_thread(message.thread.thread_hash)
        else:
            delete_post(message.message_id)
        add_mod_log_entry(
            f"Automatically deleted post with banned "
            f"file attachment hashes {', '.join(map(str, banned_hashes))}",
            message_id=message.message_id,
            board_address=message.thread.chan.address,
            thread_hash=message.thread.thread_hash)


def download_with_resume(message_id, url, file_path, proxy_type="tor", hash_val=None, timeout=15):
    """
    Performs HTTP(S) download that can be restarted if prematurely terminated.
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
        logger.info('{}: Resuming download from {:.1f} MB'.format(
            message_id[-config.ID_LENGTH:].upper(), first_byte / 1e6))
    else:
        logger.info('{}: Starting download'.format(message_id[-config.ID_LENGTH:].upper()))
    file_size = -1
    try:
        if proxy_type == "tor":
            session = get_tor_session()
            proxies = config.TOR_PROXIES
        elif proxy_type == "i2p":
            session = get_i2p_session()
            proxies = config.I2P_PROXIES
        else:
            logger.error("Unknown proxy type: {}".format(proxy_type))
            return

        ses_headers = session.head(
            url, headers={'User-Agent': generate_user_agent()}).headers
        if 'Content-length' in ses_headers:
            file_size = int(ses_headers['Content-length'])
        logger.debug('{}: File size is {}'.format(message_id[-config.ID_LENGTH:].upper(), file_size))

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
            proxies=proxies,
            headers=headers,
            stream=True,
            timeout=timeout)
        with open(tmp_file_path, file_mode) as f:
            for chunk in r.iter_content(chunk_size=block_size):
                if chunk:  # filter out keep-alive new chunks
                    f.write(chunk)
    except IOError as e:
        logger.error('{}: IO Error: {}'.format(message_id[-config.ID_LENGTH:].upper(), e))
    except Exception as e:
        logger.error('{}: Error: {}'.format(message_id[-config.ID_LENGTH:].upper(), e))
    finally:
        # rename the temp download file to the correct name if fully downloaded
        if file_size == os.path.getsize(tmp_file_path):
            # if there's a hash value, validate the file
            if hash_val and not validate_file(tmp_file_path, hash_val):
                raise Exception('{}: Error validating the file against its SHA256 hash'.format(
                    message_id[-config.ID_LENGTH:].upper()))
            shutil.move(tmp_file_path, file_path)
            return file_path
        elif file_size == -1:
            logger.error('{}: Error getting Content-Length from server: {}'.format(
                message_id[-config.ID_LENGTH:].upper(), url))


def download_and_extract(
        message_id,
        file_url,
        file_upload_settings,
        file_extracts_start_base64,
        upload_filename,
        file_path,
        file_sha256_hash,
        file_enc_cipher,
        file_enc_key_bytes,
        file_enc_password):

    logger.info("download_and_extract {}, {}, {}, {}, {}, {}, {}, {}, password={}".format(
        message_id,
        file_url,
        file_upload_settings,
        upload_filename,
        file_path,
        file_sha256_hash,
        file_enc_cipher,
        file_enc_key_bytes,
        file_enc_password))

    file_sha256_hashes_match = False
    file_size = None
    file_amount = None
    file_do_not_download = None
    file_progress = None
    file_download_successful = None
    downloaded = None
    force_allow_download = False
    download_url = None
    media_info = {}
    message_steg = {}
    resume_start_download = False

    if message_id in daemon_com.get_start_download() or resume_start_download:
        resume_start_download = True
        force_allow_download = True
        file_do_not_download = False
        daemon_com.remove_start_download(message_id)

    # save downloaded file to /tmp/
    # filename has been randomly generated, so no risk of collisions
    download_path = "/tmp/{}".format(upload_filename)

    with session_scope(config.DB_PATH) as new_session:
        settings = new_session.query(GlobalSettings).first()

        if (file_enc_cipher == "NONE" and
                settings.never_auto_download_unencrypted and
                not force_allow_download):
            logger.info(
                "{}: Instructed to never auto-download unencrypted attachments. "
                "Manual override needed.".format(
                    message_id[-config.ID_LENGTH:].upper()))
            file_do_not_download = True
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            file_progress = "Current settings prohibit automatically downloading unencrypted attachments."
            if message:
                message.file_progress = "Current settings prohibit automatically downloading unencrypted attachments."
                message.regenerate_post_html = True
                new_session.commit()
            return (file_download_successful,
                    file_size,
                    file_amount,
                    file_do_not_download,
                    file_sha256_hashes_match,
                    file_progress,
                    media_info,
                    message_steg)

        if (not settings.auto_dl_from_unknown_upload_sites and
                not is_upload_site_in_database(file_upload_settings)):
            logger.info(
                "{}: Instructed to never auto-download from unknown upload sites. "
                "Save upload site to database then instruct to download.".format(
                    message_id[-config.ID_LENGTH:].upper()))
            file_do_not_download = True
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            file_progress = "Unknown upload site detected. Add upload site and manually start download."
            if message:
                message.file_progress = file_progress
                message.regenerate_post_html = True
                new_session.commit()
            return (file_download_successful,
                    file_size,
                    file_amount,
                    file_do_not_download,
                    file_sha256_hashes_match,
                    file_progress,
                    media_info,
                    message_steg)

        if not settings.allow_net_file_size_check and not force_allow_download:
            logger.info("{}: Not connecting to determine file size. Manual override needed.".format(
                message_id[-config.ID_LENGTH:].upper()))
            file_do_not_download = True
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            file_progress = "Configuration doesn't allow getting file size. Manual override required."
            if message:
                message.file_progress = file_progress
                message.regenerate_post_html = True
                new_session.commit()
            return (file_download_successful,
                    file_size,
                    file_amount,
                    file_do_not_download,
                    file_sha256_hashes_match,
                    file_progress,
                    media_info,
                    message_steg)
        else:
            logger.info("{}: Getting URL and file size...".format(message_id[-config.ID_LENGTH:].upper()))

    # Parse page for URL to direct download zip
    if "direct_dl_url" in file_upload_settings and file_upload_settings["direct_dl_url"]:
        download_url = file_url
    else:
        try:
            logger.info("{}: Finding download URL on upload page".format(message_id[-config.ID_LENGTH:].upper()))
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
            logger.error("{}: Error getting upload page".format(message_id[-config.ID_LENGTH:].upper()))

    if not download_url:
        logger.error("{}: Could not find URL for {}".format(
            message_id[-config.ID_LENGTH:].upper(), upload_filename))
        daemon_com.remove_start_download(message_id)
        with session_scope(config.DB_PATH) as new_session:
            message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if message:
                message.file_progress = "Could not find download URL. Try again."
                message.regenerate_post_html = True
                new_session.commit()
        return (file_download_successful,
                file_size,
                file_amount,
                file_do_not_download,
                file_sha256_hashes_match,
                file_progress,
                media_info,
                message_steg)
    else:
        logger.info("{}: Found URL".format(message_id[-config.ID_LENGTH:].upper()))
        time.sleep(5)
        for _ in range(3):
            logger.info("{}: Getting file size".format(message_id[-config.ID_LENGTH:].upper()))
            try:
                if resume_start_download:
                    if ".i2p" in file_url:
                        session = get_i2p_session()
                    else:
                        session = get_tor_session()

                    headers = session.head(
                        download_url,
                        headers={'User-Agent': generate_user_agent()}).headers
                    logger.info("{}: Headers: {}".format(message_id[-config.ID_LENGTH:].upper(), headers))
                    if 'Content-length' in headers:
                        file_size = int(headers['Content-length'])
                        logger.info("{}: File size acquired: {}".format(
                            message_id[-config.ID_LENGTH:].upper(), human_readable_size(file_size)))
                        break
                    else:
                        logger.error("{}: 'content-length' not in header".format(
                            message_id[-config.ID_LENGTH:].upper()))
                else:
                    with session_scope(config.DB_PATH) as new_session:
                        settings = new_session.query(GlobalSettings).first()
                        # Don't download file if user set to 0
                        if settings.max_download_size == 0:
                            downloaded = "prohibited"
                            file_do_not_download = True
                            logger.info("{}: File prevented from being auto-download.".format(
                                message_id[-config.ID_LENGTH:].upper()))
                            break

                        # Check file size and auto-download if less than user-set size
                        if ".i2p" in file_url:
                            session = get_i2p_session()
                        else:
                            session = get_tor_session()

                        headers = session.head(
                            download_url,
                            headers={'User-Agent': generate_user_agent()}).headers
                        logger.info("{}: Headers: {}".format(message_id[-config.ID_LENGTH:].upper(), headers))
                        if 'Content-length' in headers:
                            file_size = int(headers['Content-length'])
                            if file_size and file_size > settings.max_download_size * 1024 * 1024:
                                downloaded = "too_large"
                                file_do_not_download = True
                                logger.info(
                                    "{}: File size ({}) is greater than max allowed "
                                    "to auto-download ({}). Not downloading.".format(
                                        message_id[-config.ID_LENGTH:].upper(),
                                        human_readable_size(file_size),
                                        human_readable_size(settings.max_download_size * 1024 * 1024)))
                                break
                            else:
                                file_do_not_download = False
                                logger.info(
                                    "{}: File size ({}) is less than max allowed "
                                    "to auto-download ({}). Downloading.".format(
                                        message_id[-config.ID_LENGTH:].upper(),
                                        human_readable_size(file_size),
                                        human_readable_size(settings.max_download_size * 1024 * 1024)))
                                break
                        else:
                            logger.error("{}: 'content-length' not in header".format(
                                message_id[-config.ID_LENGTH:].upper()))
                time.sleep(15)
            except Exception as err:
                logger.exception("{}: Could not get file size: {}".format(
                    message_id[-config.ID_LENGTH:].upper(), err))
                file_do_not_download = True
                time.sleep(15)

        if file_do_not_download and not force_allow_download:
            logger.info("{}: Not downloading.".format(message_id[-config.ID_LENGTH:].upper()))
            with session_scope(config.DB_PATH) as new_session:
                message = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if message:
                    message.file_progress = ("Configuration doesn't allow auto-downloading of this file. "
                                             "Manual override required.")
                    message.regenerate_post_html = True
                    new_session.commit()
            return (file_download_successful,
                    file_size,
                    file_amount,
                    file_do_not_download,
                    file_sha256_hashes_match,
                    file_progress,
                    media_info,
                    message_steg)
        else:
            logger.info("{}: Downloading...".format(message_id[-config.ID_LENGTH:].upper()))
            file_do_not_download = False
            time.sleep(5)

        for _ in range(config.DOWNLOAD_ATTEMPTS):
            try:
                if ".i2p" in file_url:
                    download_with_resume(message_id, download_url, download_path, proxy_type="i2p")
                else:
                    download_with_resume(message_id, download_url, download_path)
                if file_size == os.path.getsize(download_path):
                    break
                logger.error(
                    "{}: File size does not match what's expected. "
                    "File size: {} bytes, expected: {} bytes".format(
                        message_id[-config.ID_LENGTH:].upper(),
                        os.path.getsize(download_path),
                        file_size))
                file_progress = "Downloaded file size doesn't match reported file size"
            except IOError as err:
                file_progress = "IOError downloading: {}".format(err)
                logger.error("{}: Could not download".format(message_id[-config.ID_LENGTH:].upper()))
            except Exception as err:
                file_progress = "Exception downloading: {}".format(err)
                logger.error("{}: Exception downloading: {}".format(message_id[-config.ID_LENGTH:].upper(), err))
            time.sleep(60)

        try:
            if file_size == os.path.getsize(download_path):
                logger.info("{}: Download completed".format(message_id[-config.ID_LENGTH:].upper()))
                downloaded = "downloaded"
            else:
                logger.error("{}: Download not complete. Encountered unexpected file size. "
                             "Downloading anyway and checking hashes.".format(message_id[-config.ID_LENGTH:].upper()))
                downloaded = "downloaded"
        except:
            logger.error("{}: Issue downloading file".format(message_id[-config.ID_LENGTH:].upper()))

        if downloaded == "prohibited":
            logger.info("{}: File prohibited from auto-downloading".format(
                message_id[-config.ID_LENGTH:].upper()))
        elif downloaded == "too_large":
            with session_scope(config.DB_PATH) as new_session:
                settings = new_session.query(GlobalSettings).first()
                logger.info("{}: File size ({}) is larger than allowed to auto-download ({})".format(
                    message_id[-config.ID_LENGTH:].upper(),
                    human_readable_size(file_size),
                    human_readable_size(settings.max_download_size * 1024 * 1024)))
        elif downloaded == "downloaded":
            logger.info("{}: File successfully downloaded".format(message_id[-config.ID_LENGTH:].upper()))
            file_progress = None
            file_download_successful = True
        elif downloaded is None:
            file_progress = "Could not download file after {} attempts".format(
                config.DOWNLOAD_ATTEMPTS)
            logger.error(file_progress)
            with session_scope(config.DB_PATH) as new_session:
                message = new_session.query(Messages).filter(
                    Messages.message_id == message_id).first()
                if message:
                    message.file_progress = file_progress
                    message.regenerate_post_html = True
                    new_session.commit()
            file_download_successful = False

        if file_download_successful:
            # Add missing parts back to file
            if file_extracts_start_base64:
                size_before = os.path.getsize(download_path)
                data_file_multiple_insert(download_path, file_extracts_start_base64, chunk=4096)
                logger.info("{}: File data insertion. Before: {}, After: {}".format(
                    message_id[-config.ID_LENGTH:].upper(), size_before, os.path.getsize(download_path)))

            # compare SHA256 hashes
            if file_sha256_hash:
                if not validate_file(download_path, file_sha256_hash):
                    file_progress = (
                        "File SHA256 hash ({}) does not match provided SHA256 hash ({}). Deleting.").format(
                        generate_hash(download_path), file_sha256_hash)
                    logger.info(file_progress)
                    file_sha256_hashes_match = False
                    file_download_successful = False
                    delete_file(download_path)
                    return (file_download_successful,
                            file_size,
                            file_amount,
                            file_do_not_download,
                            file_sha256_hashes_match,
                            file_progress,
                            media_info,
                            message_steg)
                else:
                    file_sha256_hashes_match = True
                    logger.info("{}: File SHA256 hashes match ({})".format(
                        message_id[-config.ID_LENGTH:].upper(), file_sha256_hash))

            if file_enc_cipher == "NONE":
                logger.info("{}: File not encrypted".format(message_id[-config.ID_LENGTH:].upper()))
                full_path_filename = download_path
            else:
                # decrypt file
                full_path_filename = "/tmp/{}.zip".format(
                    get_random_alphanumeric_string(12, with_punctuation=False, with_spaces=False))
                delete_file(full_path_filename)  # make sure no file already exists
                logger.info("{}: Decrypting file".format(message_id[-config.ID_LENGTH:].upper()))
                with session_scope(config.DB_PATH) as new_session:
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = "Decrypting file"
                        message.regenerate_post_html = True
                        new_session.commit()

                try:
                    with session_scope(config.DB_PATH) as new_session:
                        settings = new_session.query(GlobalSettings).first()
                        ret_crypto, error_msg = crypto_multi_decrypt(
                            file_enc_cipher,
                            file_enc_password + config.PGP_PASSPHRASE_ATTACH,
                            download_path,
                            full_path_filename,
                            key_bytes=file_enc_key_bytes,
                            max_size_bytes=settings.max_extract_size * 1024 * 1024)
                        if not ret_crypto:
                            logger.error(
                                f"{message_id[-config.ID_LENGTH:].upper()}: Issue decrypting attachment: {error_msg}")
                            message = new_session.query(Messages).filter(
                                Messages.message_id == message_id).first()
                            if message:
                                message.file_progress = error_msg
                                message.regenerate_post_html = True
                                new_session.commit()
                            file_download_successful = False
                            return (file_download_successful,
                                    file_size,
                                    file_amount,
                                    file_do_not_download,
                                    file_sha256_hashes_match,
                                    file_progress,
                                    media_info,
                                    message_steg)
                    logger.info("{}: Finished decrypting file".format(message_id[-config.ID_LENGTH:].upper()))

                    # z = zipfile.ZipFile(download_path)
                    # z.setpassword(config.PGP_PASSPHRASE_ATTACH.encode())
                    # z.extract(extract_filename, path=extract_path)
                except Exception:
                    logger.exception(f"{message_id[-config.ID_LENGTH:].upper()}: Error decrypting attachment")
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = "Error decrypting attachment. Check log."
                        message.regenerate_post_html = True
                        new_session.commit()

            # Get the number of files in the zip archive
            try:
                file_amount_test = count_files_in_zip(message_id, full_path_filename)
            except Exception as err:
                with session_scope(config.DB_PATH) as new_session:
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = "Error checking zip: {}".format(
                            message_id[-config.ID_LENGTH:].upper(), err)
                        message.regenerate_post_html = True
                        new_session.commit()
                logger.error("{}: Error checking zip: {}".format(
                    message_id[-config.ID_LENGTH:].upper(), err))
                file_do_not_download = True
                return (file_download_successful,
                        file_size,
                        file_amount,
                        file_do_not_download,
                        file_sha256_hashes_match,
                        file_progress,
                        media_info,
                        message_steg)

            if file_amount_test:
                file_amount = file_amount_test

            if file_amount and file_amount > config.FILE_ATTACHMENTS_MAX:
                logger.info("{}: Number of attachments ({}) exceed the maximum ({}).".format(
                    message_id[-config.ID_LENGTH:].upper(), file_amount, config.FILE_ATTACHMENTS_MAX))
                file_do_not_download = True
                return (file_download_successful,
                        file_size,
                        file_amount,
                        file_do_not_download,
                        file_sha256_hashes_match,
                        file_progress,
                        media_info,
                        message_steg)

            # Check size of zip contents before extraction
            can_extract = True
            with zipfile.ZipFile(full_path_filename, 'r') as zipObj:
                total_size = 0
                for each_file in zipObj.infolist():
                    total_size += each_file.file_size
                logger.info(f"{message_id[-config.ID_LENGTH:].upper()}: ZIP contents size: {total_size}")
                with session_scope(config.DB_PATH) as new_session:
                    settings = new_session.query(GlobalSettings).first()
                    max_extract_size = settings.max_extract_size * 1024 * 1024
                    if settings.max_extract_size and total_size > max_extract_size:
                        can_extract = False
                        msg = "Extracted attachment size greater than allowed ({} > {}).".format(
                            human_readable_size(file_size), human_readable_size(max_extract_size))
                        logger.error(msg)
                        message = new_session.query(Messages).filter(
                            Messages.message_id == message_id).first()
                        if message:
                            message.file_progress = msg
                            message.regenerate_post_html = True
                            message.file_download_successful = False
                            new_session.commit()

            if can_extract:
                # Extract zip archive
                extract_path = "{}/{}".format(config.FILE_DIRECTORY, message_id)
                extract_zip(message_id, full_path_filename, extract_path)
                delete_file(full_path_filename)  # Secure delete

                errors_files, media_info, message_steg = process_attachments(message_id, extract_path)

                if errors_files:
                    logger.error(
                        "{}: File extension greater than {} characters. Deleting.".format(
                            message_id[-config.ID_LENGTH:].upper(), config.MAX_FILE_EXT_LENGTH))
                    delete_files_recursive(extract_path)
                    file_do_not_download = True
                    return (file_download_successful,
                            file_size,
                            file_amount,
                            file_do_not_download,
                            file_sha256_hashes_match,
                            file_progress,
                            media_info,
                            message_steg)

                with session_scope(config.DB_PATH) as new_session:
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        message.file_progress = "Attachment processing successful"
                        message.regenerate_post_html = True
                        new_session.commit()

        delete_file(download_path)

    return (file_download_successful,
            file_size,
            file_amount,
            file_do_not_download,
            file_sha256_hashes_match,
            file_progress,
            media_info,
            message_steg)


def process_attachments(message_id, extract_path, progress=True, silent=False, overwrite_thumbs=False):
    if not silent:
        logger.info("{}: Processing attachments in {}".format(
            message_id[-config.ID_LENGTH:].upper(), extract_path))
    media_info = {}
    message_steg = {}
    errors = []

    thumb_dir = "{}_thumb".format(extract_path)
    if os.path.exists(thumb_dir) and overwrite_thumbs:
        delete_files_recursive(thumb_dir)

    for dirpath, dirnames, filenames in os.walk(extract_path):
        for f in filenames:
            # Delete remnant files no longer used
            if f.startswith(f"{message_id}_thumb."):
                delete_file(os.path.join(extract_path, f))
                continue

            file_number = None
            spoiler = False
            try:
                with session_scope(config.DB_PATH) as new_session:
                    message = new_session.query(Messages).filter(
                        Messages.message_id == message_id).first()
                    if message:
                        if progress:
                            message.file_progress = "Calculating video dimensions"
                            message.regenerate_post_html = True
                            new_session.commit()

                        try:
                            file_order = json.loads(message.file_order)
                        except:
                            file_order = []

                        logger.info(f"{message_id[-config.ID_LENGTH:].upper()}: File order: {file_order}")

                        # determine if spoiler needed
                        if not file_order:
                            file_order = []

                        for i, each_file in enumerate(file_order, start=1):
                            if f == each_file:
                                file_number = i
                                if i == 1:
                                    spoiler = message.image1_spoiler
                                elif i == 2:
                                    spoiler = message.image2_spoiler
                                elif i == 3:
                                    spoiler = message.image3_spoiler
                                elif i == 4:
                                    spoiler = message.image4_spoiler
                                break
                    else:
                        errors.append(f"Could not find database entry for message with ID {message_id}")
                        return errors, media_info, message_steg
            except:
                pass

            if not file_number:
                errors.append("Could not determine file number, not attempting to generating thumbnails.")
                return errors, media_info, message_steg

            try:
                fp = os.path.join(dirpath, f)
                if not silent:
                    logger.info("{}: Processing attachment {}".format(
                        message_id[-config.ID_LENGTH:].upper(), fp))
                if os.path.islink(fp):  # skip symbolic links
                    continue

                file_extension = html.escape(os.path.splitext(f)[1].split(".")[-1].lower())
                attachment_size = os.path.getsize(fp)
                media_height = None
                media_width = None
                exif = None
                steg_msg = None
                imagehash_hash = None

                if len(file_extension) >= config.MAX_FILE_EXT_LENGTH:
                    errors.append("File extension lengths must be less than {}: {}".format(
                        config.MAX_FILE_EXT_LENGTH, f))

                elif file_extension in config.FILE_EXTENSIONS_IMAGE:
                    if not silent:
                        logger.info("{}: Attachment is an image".format(
                            message_id[-config.ID_LENGTH:].upper()))
                    # If image file, check for steg message
                    with session_scope(config.DB_PATH) as new_session:
                        pgp_passphrase_steg = config.PGP_PASSPHRASE_STEG
                        message = new_session.query(Messages).filter(
                            Messages.message_id == message_id).first()
                        if (message and
                                message.thread and
                                message.thread.chan and
                                message.thread.chan.pgp_passphrase_steg):
                            pgp_passphrase_steg = message.thread.chan.pgp_passphrase_steg

                        if not silent:
                            logger.info("{}: Checking for steg".format(
                                message_id[-config.ID_LENGTH:].upper()))
                        steg_msg = check_steg(
                            message_id,
                            file_extension,
                            passphrase=pgp_passphrase_steg,
                            file_path=fp)

                        if message and progress:
                            message.file_progress = "Generating image thumbnail"
                            message.regenerate_post_html = True
                            new_session.commit()

                    if not silent:
                        logger.info("{}: Generating thumbnail(s)".format(
                            message_id[-config.ID_LENGTH:].upper()))

                    try:
                        os.mkdir(thumb_dir)
                    except:
                        pass
                    img_thumb_filename = f"{thumb_dir}/thumb_{file_number}.jpg"
                    image_thumb_spoiler_filename = None
                    if spoiler:
                        image_thumb_spoiler_filename = f"{thumb_dir}/thumb_{file_number}_spoiler.jpg"

                    generate_thumbnail_image(
                        message_id, fp, img_thumb_filename, file_extension,
                        spoiler_filename=image_thumb_spoiler_filename,
                        overwrite_thumbs=overwrite_thumbs)

                    try:
                        img = Image.open(fp)
                        try:
                            with session_scope(config.DB_PATH) as new_session:
                                message = new_session.query(Messages).filter(
                                    Messages.message_id == message_id).first()
                                if message and progress:
                                    message.file_progress = "Calculating image dimensions"
                                    message.regenerate_post_html = True
                                    new_session.commit()
                            if not silent:
                                logger.info("{}: Determining image dimensions".format(
                                    message_id[-config.ID_LENGTH:].upper()))
                            Image.MAX_IMAGE_PIXELS = 500000000
                            media_width, media_height = img.size
                        except UnidentifiedImageError as e:
                            logger.exception("{}: Error identifying image: {}".format(
                                message_id[-config.ID_LENGTH:].upper(), e))
                        except Exception as e:
                            logger.exception("{}: Error opening/stripping image: {}".format(
                                message_id[-config.ID_LENGTH:].upper(), e))

                        # get image fingerprint
                        try:
                            imagehash_hash = str(imagehash.average_hash(img))
                        except:
                            logger.exception(f"{message_id[-config.ID_LENGTH:].upper()}: Generating image hash")

                        # get image metadata
                        try:
                            exif = []
                            img_exif = img.getexif()

                            if img_exif is not None:
                                for key, val in img_exif.items():
                                    if key in ExifTags.TAGS:
                                        exif.append(f'{ExifTags.TAGS[key]}: {val}')
                                    else:
                                        exif.append(f'{key}: {val}')
                                exif.sort()
                        except:
                            logger.exception(f"{message_id[-config.ID_LENGTH:].upper()}: Getting exif data")
                    except:
                        logger.exception("Could not open image")

                elif file_extension in config.FILE_EXTENSIONS_VIDEO:
                    try:
                        try:
                            os.mkdir(thumb_dir)
                        except:
                            pass

                        video_thumb_filename = f"{thumb_dir}/thumb_{file_number}.jpg"
                        video_thumb_spoiler_filename = None
                        if spoiler:
                            video_thumb_spoiler_filename = f"{thumb_dir}/thumb_{file_number}_spoiler.jpg"

                        if not silent:
                            logger.info("{}: Generating video thumbnail {} with {}".format(
                                message_id[-config.ID_LENGTH:].upper(), video_thumb_filename, fp))

                        generate_thumbnail_video(
                            message_id, fp, video_thumb_filename,
                            spoiler_filename=video_thumb_spoiler_filename,
                            overwrite_thumbs=overwrite_thumbs)

                        if not silent:
                            logger.info("{}: Determining video dimensions".format(
                                message_id[-config.ID_LENGTH:].upper()))

                        vid = cv2.VideoCapture(fp)
                        media_height = vid.get(cv2.CAP_PROP_FRAME_HEIGHT)
                        media_width = vid.get(cv2.CAP_PROP_FRAME_WIDTH)

                        if not silent:
                            logger.info("{}: Video dimensions: {}x{}".format(
                                message_id[-config.ID_LENGTH:].upper(), media_width, media_height))
                    except Exception as e:
                        logger.exception("{}: Error getting video dimensions: {}".format(
                            message_id[-config.ID_LENGTH:].upper(), e))

                media_info[f] = {}
                if media_height is not None:
                    media_info[f]["height"] = media_height
                if media_width is not None:
                    media_info[f]["width"] = media_width

                # Calculate width and height percentages to determine thumbnail dimensions
                if media_height is not None and media_width is not None and media_height < media_width:
                    media_info[f]["thumb_percent_height"] = media_height / media_width
                else:
                    media_info[f]["thumb_percent_height"] = 1

                if exif:
                    media_info[f]["exif"] = exif

                media_info[f]["size"] = attachment_size
                media_info[f]["extension"] = file_extension

                # generate hashes of file
                if imagehash_hash:
                    media_info[f]["imagehash_hash"] = imagehash_hash
                media_info[f]["sha256_hash"] = generate_hash(fp)

                if steg_msg:
                    message_steg[f] = steg_msg

            except Exception:
                logger.exception("{}: Error processing file: {}".format(message_id[-config.ID_LENGTH:].upper(), f))

        break  # only look in first directory

    # Add media info to database
    with session_scope(config.DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if message:
            message.media_info = json.dumps(media_info)
            message.message_steg = json.dumps(message_steg)
            new_session.commit()

    if not silent:
        logger.info(f"{message_id[-config.ID_LENGTH:].upper()}: Finished processing attachments")

    return errors, media_info, message_steg


def is_upload_site_in_database(file_upload_settings):
    with session_scope(config.DB_PATH) as new_session:
        upload_site = new_session.query(UploadSites)

        list_columns_keys = [
            (UploadSites.domain, "domain"),
            (UploadSites.type, "type"),
            (UploadSites.subtype, "subtype"),
            (UploadSites.uri, "uri"),
            (UploadSites.download_prefix, "download_prefix"),
            (UploadSites.response, "response"),
            (UploadSites.json_key, "json_key"),
            (UploadSites.direct_dl_url, "direct_dl_url"),
            (UploadSites.extra_curl_options, "extra_curl_options"),
            (UploadSites.upload_word, "upload_word"),
            (UploadSites.http_headers, "http_headers"),
            (UploadSites.proxy_type, "proxy_type"),
            (UploadSites.replace_download_domain, "replace_download_domain")
        ]

        for column, key in list_columns_keys:
            if key not in file_upload_settings:
                continue

            if not file_upload_settings[key]:
                upload_site = upload_site.filter(
                    or_(column == "",
                        column.is_(None),
                        column.is_(False)
                        )
                )
            else:
                upload_site = upload_site.filter(
                    column == file_upload_settings[key])

        upload_site = upload_site.first()

        if upload_site:
            return True
        else:
            return False

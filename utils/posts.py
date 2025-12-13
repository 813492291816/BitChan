import json
import logging
import os
import time

import qbittorrentapi
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import BanedHashes
from database.models import Chan
from database.models import DeletedThreads
from database.models import Games
from database.models import Messages
from database.models import PostCards
from database.models import PostDeletePasswordHashes
from database.models import Threads
from database.models import UploadTorrents
from database.utils import session_scope
from utils.files import delete_file
from utils.files import delete_message_files
from utils.replacements import is_board_post_reply
from utils.replacements import is_post_id_reply
from utils.replacements import is_post_reference_valid
from utils.shared import get_post_id
from utils.shared import regenerate_ref_to_from_post

daemon_com = DaemonCom()

logger = logging.getLogger('bitchan.posts')


def delete_message_replies(message_id):
    post_id = get_post_id(message_id)
    with session_scope(config.DB_PATH) as new_session:
        messages = new_session.query(Messages).filter(
            Messages.post_ids_replying_to_msg.contains(post_id)).all()
        for each_entry in messages:
            try:
                replies = json.loads(each_entry.post_ids_replying_to_msg)
                replies.remove(post_id)
                each_entry.post_ids_replying_to_msg = json.dumps(replies)
            except:
                pass

            message = new_session.query(Messages).filter(
                Messages.post_id == each_entry.post_id).first()
            if message:
                message.regenerate_post_html = True
                new_session.commit()

        new_session.commit()


def delete_post_delete_password(message_id):
    """Delete the entry that stores the password hash that's used to delete a post using a password"""
    with session_scope(config.DB_PATH) as new_session:
        hash_delete = new_session.query(PostDeletePasswordHashes).filter(
            PostDeletePasswordHashes.message_id == message_id).first()
        if hash_delete:
            new_session.delete(hash_delete)


def delete_message_torrent(message_id):
    with session_scope(config.DB_PATH) as new_session:
        torrent = new_session.query(UploadTorrents).filter(
            UploadTorrents.message_id == message_id).first()
        if not torrent:
            logger.error(f"Torrent not found for message with ID {message_id}")
            return

        # Delete torrent through qbittorrent
        conn_info = dict(host=config.QBITTORRENT_HOST, port=8080)
        qbt_client = qbittorrentapi.Client(**conn_info)
        try:
            qbt_client.auth_log_in()
            with qbittorrentapi.Client(**conn_info) as qbt_client:
                qbt_client.torrents_delete(delete_files=True, torrent_hashes=torrent.torrent_hash)
        except Exception:
            logger.exception(f"Error deleting torrent")

        # For good measure, attempt to delete where data and torrent file (if qbittorrent api failed ot delete)
        path_data = os.path.join('/i2p_qb/Downloads/', torrent.file_hash)
        path_data_zip = os.path.join('/i2p_qb/Downloads/', f"{torrent.file_hash}.zip")
        path_torrent = os.path.join('/i2p_qb/torrent_autostart/', f"{torrent.file_hash}.torrent")
        delete_file(path_data)
        delete_file(path_data_zip)
        delete_file(path_torrent)

        new_session.delete(torrent)  # Delete DB entry


def delete_chan(address):
    logger.info(f"Deleting chan {address} from BitChan database.")
    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == address).first()
        if chan:
            new_session.delete(chan)
            new_session.commit()


def delete_post(message_id, only_hide=False):
    with session_scope(config.DB_PATH) as new_session:
        message = new_session.query(Messages).join(Threads).filter(and_(
            Messages.message_id == message_id,
            Threads.archived.is_not(True))).first()
        if message:
            thread_hash = message.thread.thread_hash
            chan_id = message.thread.chan.id
            chan_address = message.thread.chan.address

            # Signal card needs to be rendered again
            card = new_session.query(PostCards).filter(
                PostCards.thread_id == thread_hash).first()
            if card:
                card.regenerate = True
                new_session.commit()

            if only_hide:
                regenerate_ref_to_from_post(message_id)
                message.hide = True
                message.hide_ts = time.time()
                message.regenerate_popup_html = True
                message.regenerate_post_html = True
                new_session.commit()
                return

            new_session.expunge_all()

    # Not only hiding, proceed with full deletion
    if message:
        # Delete all files associated with message
        delete_message_files(message_id)

        # Delete password hash entry for post deletion
        delete_post_delete_password(message_id)

        # Delete reply entry and references to post ID
        delete_message_replies(message_id)

        # Delete torrent associated with post
        delete_message_torrent(message_id)

        # Add deleted message entry
        daemon_com.trash_message(message_id)

        with session_scope(config.DB_PATH) as new_session:
            # Indicate which board needs to regenerate post numbers
            chan = new_session.query(Chan).filter(
                Chan.id == chan_id).first()
            if chan:
                chan.regenerate_numbers = True
                new_session.commit()

        regenerate_ref_to_from_post(message_id, delete_message=True)

        # Update thread timestamp
        update_thread_timestamp(thread_hash)

        # Update board timestamp
        if chan_address:
            update_board_timestamp(chan_address)


def delete_thread(thread_id, only_hide=False):
    with session_scope(config.DB_PATH) as new_session:
        card = new_session.query(PostCards).filter(
            PostCards.thread_id == thread_id).first()
        if card:
            new_session.delete(card)
            new_session.commit()

        thread = new_session.query(Threads).filter(and_(
            Threads.thread_hash == thread_id,
            Threads.archived.is_not(True))).first()
        if thread:
            if only_hide:
                thread.hide = True
                thread.hide_ts = time.time()
                new_session.commit()
                return

            thread_hash = thread.thread_hash
            subject = thread.subject
            board_address = thread.chan.address
            new_session.delete(thread)
            new_session.commit()

            # Store deleted thread ID to discard future posts to this thread
            deleted_thread = DeletedThreads()
            deleted_thread.thread_hash = thread_hash
            deleted_thread.subject = subject
            deleted_thread.board_address = board_address
            deleted_thread.timestamp_utc = time.time()
            new_session.add(deleted_thread)
            new_session.commit()

            if board_address:
                update_board_timestamp(board_address)

            # Delete any games associated with thread
            games = new_session.query(Games).filter(
                Games.thread_hash == thread_hash).all()
            for each_game in games:
                new_session.delete(each_game)
            new_session.commit()


def check_address_for_ban(board_address, string_address):
    if board_address and string_address and board_address == string_address.replace(" ", ""):
        return True
    if "," in string_address:
        list_addresses = string_address.replace(" ", "").split(",")
        if board_address in list_addresses:
            return True


def file_hash_banned(list_hashes, address=None):
    banned_hashes = []
    with session_scope(config.DB_PATH) as new_session:
        for each_hash in list_hashes:
            if each_hash:
                banned_hash = new_session.query(BanedHashes).filter(
                    BanedHashes.hash == each_hash).first()
                banned_imagehash = new_session.query(BanedHashes).filter(
                    BanedHashes.imagehash == each_hash).first()
                if banned_hash:
                    if not address or not banned_hash.only_board_address or (
                            address and
                            banned_hash.only_board_address and
                            check_address_for_ban(address, banned_hash.only_board_address)):
                        banned_hashes.append((banned_hash.hash, banned_hash.name))
                if banned_imagehash:
                    if not address or not banned_imagehash.only_board_address or (
                            address and
                            banned_imagehash.only_board_address and
                            check_address_for_ban(address, banned_imagehash.only_board_address)):
                        banned_hashes.append((banned_imagehash.imagehash, banned_imagehash.name))
    return banned_hashes


def restore_post(message_id):
    with session_scope(config.DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        thread_hash = message.thread.thread_hash
        if message:
            # Signal card needs to be rendered again
            card = new_session.query(PostCards).filter(
                PostCards.thread_id == thread_hash).first()
            if card:
                card.regenerate = True

            message.delete_comment = None
            message.hide = False
            message.hide_ts = time.time()
            message.regenerate_popup_html = True
            message.regenerate_post_html = True
            new_session.commit()

    regenerate_ref_to_from_post(message_id)


def restore_thread(thread_id):
    with session_scope(config.DB_PATH) as new_session:
        thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_id).first()
        if thread:
            thread.hide = False
            thread.hide_ts = time.time()
            new_session.commit()


def update_board_timestamp(address):
    """ Update board timestamp """
    logger.debug(f"Updating board {address} timestamps")
    with session_scope(config.DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == address).first()
        if chan:
            thread = new_session.query(Threads).filter(
                Threads.chan_id == chan.id).order_by(
                    Threads.timestamp_sent.desc()).first()
            if thread and thread.timestamp_sent:
                logger.debug(f"Updating chan {address} timestamp_sent to "
                             f"{thread.timestamp_sent} (from thread {thread.thread_hash})")
                chan.timestamp_sent = thread.timestamp_sent
                new_session.commit()

            thread = new_session.query(Threads).filter(
                Threads.chan_id == chan.id).order_by(
                Threads.timestamp_received.desc()).first()
            if thread and thread.timestamp_received:
                logger.debug(f"Updating chan {address} timestamp_received to "
                             f"{thread.timestamp_sent} (from thread {thread.thread_hash})")
                chan.timestamp_received = thread.timestamp_received
                new_session.commit()


def update_thread_timestamp(thread_hash):
    """ Update thread timestamp """
    logger.debug(f"Updating thread {thread_hash} timestamps")
    with session_scope(config.DB_PATH) as new_session:
        thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_hash).first()
        if thread:
            message_latest = new_session.query(Messages).filter(
                Messages.thread_id == thread.id).order_by(
                    Messages.timestamp_sent.desc()).first()
            if message_latest and message_latest.timestamp_sent:
                logger.debug(f"Updating thread {thread.thread_hash} timestamp_sent to "
                             f"{message_latest.timestamp_sent} (from msg {message_latest.message_id})")
                thread.timestamp_sent = message_latest.timestamp_sent
                new_session.commit()

            message_latest = new_session.query(Messages).filter(
                Messages.thread_id == thread.id).order_by(
                Messages.timestamp_received.desc()).first()
            if message_latest and message_latest.timestamp_received:
                logger.debug(f"Updating thread {thread.thread_hash} timestamp_received to "
                             f"{message_latest.timestamp_received} (from msg {message_latest.message_id})")
                thread.timestamp_received = message_latest.timestamp_received
                new_session.commit()


def process_message_replies(message_id, message, thread_hash, chan_address):
    replies = []

    with session_scope(config.DB_PATH) as new_session:
        # Check for post replies
        if message:
            lines = message.split("<br/>")
            for line in lines:
                for each_find in is_post_id_reply(line):
                    if is_post_reference_valid(each_find["id"], each_find["location"], thread_hash, chan_address):
                        replies.append(each_find["id"])

                for each_find in is_board_post_reply(line):
                    replies.append(each_find[1].split("/")[1])

        # Add to post reply table
        if replies:
            this_post_id = message_id[-config.ID_LENGTH:].upper()
            for each_reply_id in replies:
                post_replied_to = new_session.query(Messages).filter(
                    Messages.post_id == each_reply_id).first()
                if post_replied_to:
                    try:
                        reply_ids = json.loads(post_replied_to.post_ids_replying_to_msg)
                    except:
                        reply_ids = []
                    if this_post_id not in reply_ids:
                        reply_ids.append(this_post_id)

                        # If reply IDs change, regenerate post html
                        if post_replied_to.post_ids_replying_to_msg != json.dumps(reply_ids):
                            post_replied_to.regenerate_post_html = True
                            post_replied_to.post_ids_replying_to_msg = json.dumps(reply_ids)
                            new_session.commit()

    return replies

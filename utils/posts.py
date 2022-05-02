import json
import logging
import time

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import DeletedThreads
from database.models import Games
from database.models import Messages
from database.models import PostCards
from database.models import Threads
from database.utils import session_scope
from utils.files import delete_message_files
from utils.replacements import is_board_post_reply
from utils.replacements import is_post_id_reply
from utils.shared import get_post_id
from utils.shared import regenerate_card_popup_post_html
from utils.shared import regenerate_ref_to_from_post

daemon_com = DaemonCom()

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.posts')


def delete_message_replies(message_id):
    post_id = get_post_id(message_id)
    with session_scope(DB_PATH) as new_session:
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


def delete_chan(address):
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == address).first()
        if chan:
            new_session.delete(chan)
            new_session.commit()


def delete_post(message_id, only_hide=False):
    with session_scope(DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        thread_hash = message.thread.thread_hash
        chan_id = message.thread.chan.id
        chan_address = message.thread.chan.address
        if message:
            # Signal card needs to be rendered again
            card = new_session.query(PostCards).filter(
                PostCards.thread_id == thread_hash).first()
            if card:
                card.regenerate = True

            if only_hide:
                message.hide = True
                message.hide_ts = time.time()
                message.regenerate_popup_html = True
                message.regenerate_post_html = True
                new_session.commit()
                return

            # Delete all files associated with message
            delete_message_files(message.message_id)

            # Delete reply entry and references to post ID
            delete_message_replies(message.message_id)

            # Add deleted message entry
            daemon_com.trash_message(message_id)

            # Indicate which board needs to regenerate post numbers
            chan = new_session.query(Chan).filter(
                Chan.id == chan_id).first()
            if chan:
                chan.regenerate_numbers = True

            # Update thread timestamp
            update_thread_timestamp(thread_hash)

            # Update board timestamp
            update_board_timestamp(chan_address)

    if only_hide:
        regenerate_ref_to_from_post(message_id)
    else:
        regenerate_ref_to_from_post(message_id, delete_message=True)


def restore_post(message_id):
    with session_scope(DB_PATH) as new_session:
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
    with session_scope(DB_PATH) as new_session:
        thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_id).first()
        if thread:
            thread.hide = False
            thread.hide_ts = time.time()
            new_session.commit()


def delete_thread(thread_id, only_hide=False):
    with session_scope(DB_PATH) as new_session:
        card = new_session.query(PostCards).filter(
            PostCards.thread_id == thread_id).first()
        if card:
            new_session.delete(card)
            new_session.commit()

        thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_id).first()
        if thread:
            if only_hide:
                thread.hide = True
                thread.hide_ts = time.time()
                new_session.commit()
                return

            thread_hash = thread.thread_hash
            board_address = thread.chan.address
            new_session.delete(thread)
            new_session.commit()

            # Store deleted thread ID to discard future posts to this thread
            deleted_thread = DeletedThreads()
            deleted_thread.thread_hash = thread_hash
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


def update_board_timestamp(address):
    """ Update board timestamp """
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == address).first()
        if chan:
            thread = new_session.query(Threads).filter(
                Threads.chan_id == chan.id).order_by(
                    Threads.timestamp_sent.desc()).first()
            if thread and thread.timestamp_sent:
                chan.timestamp_sent = thread.timestamp_sent
                new_session.commit()


def update_thread_timestamp(thread_hash):
    """ Update thread timestamp """
    with session_scope(DB_PATH) as new_session:
        thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_hash).first()
        if thread:
            message_latest = new_session.query(Messages).filter(
                Messages.thread_id == thread.id).order_by(
                    Messages.timestamp_sent.desc()).first()
            if message_latest:
                thread.timestamp_sent = message_latest.timestamp_sent
                new_session.commit()


def process_message_replies(message_id, message):
    replies = []

    with session_scope(DB_PATH) as new_session:
        # Check for post replies
        if message:
            lines = message.split("<br/>")
            for line in lines:
                # Find Reply IDs
                dict_post_ids_strings = is_post_id_reply(line)
                if dict_post_ids_strings:
                    for each_string, targetpostdata in dict_post_ids_strings.items():
                        replies.append(targetpostdata["id"])

                dict_board_ids_strings = is_board_post_reply(line)
                if dict_board_ids_strings:
                    for each_string, targetpostdata in dict_board_ids_strings.items():
                        board_post_id = targetpostdata.split("/")[1]
                        replies.append(board_post_id)

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

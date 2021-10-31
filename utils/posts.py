import json
import logging

import config
from bitchan_client import DaemonCom
from database.models import Chan
from database.models import Messages
from database.models import PostCards
from database.models import PostReplies
from database.models import Threads
from database.utils import session_scope
from utils.files import delete_message_files
from utils.message_summary import get_post_id
from utils.replacements import is_board_post_reply
from utils.replacements import is_post_id_reply

daemon_com = DaemonCom()

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.posts')


def delete_message_replies(message_id):
    post_id = get_post_id(message_id)
    with session_scope(DB_PATH) as new_session:
        reply_entries = new_session.query(PostReplies).filter(
            PostReplies.reply_ids.contains(post_id)).all()
        for each_entry in reply_entries:
            replies = json.loads(each_entry.reply_ids)
            replies.remove(post_id)
            each_entry.reply_ids = json.dumps(replies)
        new_session.commit()

        # delete reply entry
        reply_entry = new_session.query(PostReplies).filter(
            PostReplies.post_id == post_id).first()
        if reply_entry:
            new_session.delete(reply_entry)


def delete_chan(address):
    with session_scope(DB_PATH) as new_session:
        chan = new_session.query(Chan).filter(
            Chan.address == address).first()
        if chan:
            new_session.delete(chan)
            new_session.commit()


def delete_post(message_id):
    with session_scope(DB_PATH) as new_session:
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        thread_hash = message.thread.thread_hash
        chan_id = message.thread.chan.id
        if message:
            # Delete all files associated with message
            delete_message_files(message.message_id)

            # Delete reply entry and references to post ID
            delete_message_replies(message.message_id)

            # Add deleted message entry
            daemon_com.trash_message(message_id)

            # Signal card needs to be rendered again
            card = new_session.query(PostCards).filter(
                PostCards.thread_id == thread_hash).first()
            if card:
                card.regenerate = True

            # Indicate which board needs to regenerate post numbers
            chan = new_session.query(Chan).filter(
                Chan.id == chan_id).first()
            if chan:
                chan.regenerate_numbers = True

            # Delete message from database
            new_session.delete(message)
            new_session.commit()

            # Update thread timestamp to last current post timestamp
            thread = new_session.query(Threads).filter(
                Threads.thread_hash == thread_hash).first()
            if thread:
                message_latest = new_session.query(Messages).filter(
                    Messages.thread_id == thread.id).order_by(
                        Messages.timestamp_sent.desc()).first()
                if message_latest:
                    thread.timestamp_sent = message_latest.timestamp_sent
                    new_session.commit()

                # Update board timestamp to latest thread timestamp
                board = new_session.query(Chan).filter(
                    Chan.id == thread.chan_id).first()
                if board:
                    latest_thread = new_session.query(Threads).filter(
                        Threads.chan_id == board.id).order_by(
                            Threads.timestamp_sent.desc()).first()
                    if latest_thread:
                        board.timestamp_sent = latest_thread.timestamp_sent
                        new_session.commit()


def delete_thread(thread_id):
    with session_scope(DB_PATH) as new_session:
        card = new_session.query(PostCards).filter(
            PostCards.thread_id == thread_id).first()
        if card:
            new_session.delete(card)
            new_session.commit()

        thread = new_session.query(Threads).filter(
            Threads.thread_hash == thread_id).first()
        if thread:
            new_session.delete(thread)
            new_session.commit()


def process_message_replies(message_id, message):
    with session_scope(DB_PATH) as new_session:
        # Check for post replies
        replies = []
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
                post_replied_to = new_session.query(PostReplies).filter(
                    PostReplies.post_id == each_reply_id).first()
                if post_replied_to:
                    reply_ids = json.loads(post_replied_to.reply_ids)
                    if this_post_id not in reply_ids:
                        reply_ids.append(this_post_id)
                        post_replied_to.reply_ids = json.dumps(reply_ids)
                else:
                    new_post_replies = PostReplies()
                    new_post_replies.post_id = each_reply_id
                    new_post_replies.reply_ids = json.dumps([this_post_id])
                    new_session.add(new_post_replies)
                new_session.commit()

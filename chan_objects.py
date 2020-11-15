import json
import logging
import random
from urllib.parse import urlparse

import bleach
from sortedcontainers import SortedListWithKey

import config
from database.models import Messages
from database.utils import session_scope
from utils.download import download_and_extract
from utils.files import LF
from utils.general import get_random_alphanumeric_string

DB_PATH = 'sqlite:///' + config.DATABASE_BITCHAN

logger = logging.getLogger('bitchan.chan_objects')


class ChanPost:
    def __init__(self, message_id):
        self.thread_id = None
        self.target_posts = set([])

        self.message_id = bleach.clean(message_id)
        self.post_id = self.message_id[-config.ID_LENGTH:].upper()

        with session_scope(DB_PATH) as new_session:
            message_post = new_session.query(Messages).filter(
                Messages.message_id == self.message_id).first()
            if message_post and message_post.thread and message_post.thread.chan:
                self.thread_id = message_post.thread.thread_hash
                self.timestamp = message_post.timestamp_received
                self.subject = message_post.subject
                self.from_address = message_post.address_from
                self.to_address = message_post.thread.chan.address
                self.chan = message_post.thread.chan.address

                # Check for post replies
                if message_post.replies:
                    for each_reply in json.loads(message_post.replies):
                        self.target_posts.add(each_reply)

    def allow_download(self):
        try:
            with session_scope(DB_PATH) as new_session:
                message = new_session.query(Messages).filter(
                    Messages.message_id == self.message_id).first()
                if message:
                    file_path = "{}/{}".format(
                        config.FILE_DIRECTORY, message.saved_file_filename)
                    img_thumb_filename = "{}/{}".format(
                        config.FILE_DIRECTORY, message.saved_image_thumb_filename)
                    download_path = "/tmp/{}.zip".format(get_random_alphanumeric_string(
                        30, with_punctuation=False, with_spaces=False))

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
                             file_do_not_download,
                             file_md5_hashes_match,
                             media_height,
                             media_width,
                             message_steg) = download_and_extract(
                                self.message_id,
                                message.file_url,
                                json.loads(message.file_extracts_start_base64),
                                message.upload_filename,
                                download_path,
                                file_path,
                                message.file_extension,
                                message.file_md5_hash,
                                img_thumb_filename)
                        finally:
                            lf.lock_release(lockfile)

                    if file_download_successful:
                        message.file_size = file_size
                        message.media_height = media_height
                        message.media_width = media_width
                        message.file_download_successful = file_download_successful
                        message.file_do_not_download = file_do_not_download
                        message.file_md5_hashes_match = file_md5_hashes_match
                        message.message_steg = message_steg
                        new_session.commit()
        except Exception as e:
            logger.error("Error allowing download: {}".format(e))
        finally:
            with session_scope(DB_PATH) as new_session:
                message = new_session.query(Messages).filter(
                    Messages.message_id == self.message_id).first()
                message.file_currently_downloading = False
                new_session.commit()


class ChanThread:
    def __init__(self, chan, thread_id):
        self.posts = SortedListWithKey(key=lambda post: post.timestamp)
        # post_id -> set(replies)
        self.replies_by_post_id = {}
        self.timestamp = 0
        self.thread_id = thread_id
        self.chan = chan

    def get_posts(self):
        return self.posts

    def delete_post(self, post):
        try:
            self.posts.remove(post)
        except Exception as e:
            logger.exception("Exception removing post: {}".format(e))

    def add_post(self, post):
        self.posts.add(post)
        self.update_post_links(post)
        if post.timestamp > self.timestamp:
            self.timestamp = post.timestamp

    def update_post_links(self, post):
        for postId in post.target_posts:
            if postId not in self.replies_by_post_id:
                self.replies_by_post_id[postId] = set([])
            self.replies_by_post_id[postId].add(post.post_id)

    def get_post_replies(self, post_id):
        if post_id not in self.replies_by_post_id:
            return set([])
        return self.replies_by_post_id[post_id]


class ChanList:
    def __init__(self, chan):
        self.chan = chan

    def add_to_list(self, post):
        pass


class ChanBoard:
    def __init__(self, chan):
        self._threads = SortedListWithKey(key=lambda thread: -thread.timestamp)
        self._threads_by_id = {}
        self.chan = chan

    def get_thread_count(self):
        return len(self._threads_by_id)

    def get_threads(self, start_index, end_index):
        return self._threads[start_index:end_index]

    def get_thread(self, thread_id):
        if thread_id in self._threads_by_id:
            return self._threads_by_id[thread_id]
        return None

    def delete_post(self, post):
        thread = self.get_thread(post.thread_id)
        if thread:
            thread.delete_post(post)

    def delete_thread(self, thread_id):
        if thread_id in self._threads_by_id:
            thread = self._threads_by_id[thread_id]
            self._threads.remove(thread)

    def add_post(self, post, thread_id):
        thread_id = thread_id
        thread = self.get_thread(thread_id)

        if not thread:
            thread = ChanThread(self.chan, thread_id)
            self._threads_by_id[thread.thread_id] = thread
        else:
            # Remove it because we need to re-insert it in sorted order
            self._threads.remove(thread)

        # logger.info("Updating thread: {}".format(thread.subject))

        thread.add_post(post)
        self._threads.add(thread)

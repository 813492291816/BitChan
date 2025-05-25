import html
import json
import logging
import os
from urllib.parse import quote

from bs4 import BeautifulSoup
from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from database.models import Command
from database.models import Messages
from database.models import Threads
from database.utils import session_scope
from forms.nations import nations
from utils.files import human_readable_size
from utils.general import timestamp_to_date
from utils.html_truncate import truncate
from utils.shared import get_access

daemon_com = DaemonCom()
logger = logging.getLogger("bitchan.generate_popup")


def generate_reply_link_and_popup_html(
        message,
        name_str=None,
        class_reference=False,
        external_thread=False,
        external_board=False,
        self_post=False,
        link_text=None,
        non_link_text=None,
        font_size=None,
        extra_style="",
        moderating=False,
        use_thread_id=False,
        use_thread_hash=False,
        board_view=False):
    """ Generate a hyperlink with a hover popup of a post """
    if use_thread_id:
        message = Messages.query.filter(Messages.thread_id == use_thread_id).first()

    if use_thread_hash:
        thread = Threads.query.filter(Threads.thread_hash == use_thread_hash).first()
        if thread:
            message = Messages.query.filter(
                and_(
                    Messages.thread_id == thread.id,
                    Messages.is_op.is_(True))).first()

    if not message:
        msg = "Could not find message"
        logger.error(msg)
        if non_link_text:
            return non_link_text
        else:
            return msg

    link_str = ''
    ret_str = ''

    try:
        if link_text:
            link_str = link_text
        elif external_thread:
            # The generated link text for external threads (e.g. >>>ASDF1234)
            link_str = f'&gt;&gt;&gt;{message.post_id}'
        else:
            # The generated link text for same thread (e.g. >>ASDF1234)
            link_str = f'&gt;&gt;{message.post_id}'

        if name_str:
            link_str += name_str

        # Header reply links are smaller font with the use of "reference" class
        classes_str = ''
        if class_reference:
            classes_str += ' reference'

        if self_post and external_board:
            classes_str += ' under-wavy'
        elif self_post:
            classes_str += ' under-dash'
        elif external_board:
            classes_str += ' under-double'
        else:
            classes_str += ' under-solid'

        style_str = ''
        if font_size or extra_style:
            style_str += f' style="'
            if font_size:
                style_str += f'font-size: {font_size};'
            if extra_style:
                style_str += f'{extra_style}'
            style_str += '"'

        # If board is unlisted/restricted, don't link from outside the board to the unlisted board's post (non-link post)
        if external_board and (message.thread.chan.unlisted or message.thread.chan.restricted):
            ret_str += f'<span class="crosslink reply-tooltip{classes_str}"{style_str} title="Unlisted/Restricted">{link_str}</span>'
            return ret_str

        if use_thread_id or board_view or external_thread:
            post_url = f"/thread/{message.thread.chan.address}/{message.thread.thread_hash_short}#{message.post_id}"
        else:
            post_url = f"#{message.post_id}"

        ret_str += f'<a class="crosslink reply-tooltip{classes_str}"{style_str} href="{post_url}">{link_str}<div class="reply-main">'

        if external_thread:
            ret_str += (f'<div class="reply-header link">/{message.thread.chan.label}/ - {message.thread.chan.description}</div>'
                        f'<div class="reply-break"></div>')

        ret_str += f'<div class="reply-header themed">{generate_popup_post_header(message, external_thread=external_thread)}</div>' \
                   '<div class="reply-break"></div>'

        ret_str += generate_popup_post_body_file_info(message)

        # TODO: Refactor this to make more readable
        if moderating and message.popup_moderate and message.hide:
            ret_str += message.popup_moderate

        elif not moderating and message.popup_html and not message.regenerate_popup_html:
            ret_str += message.popup_html

        else:
            message_edit = Messages.query.filter(
                Messages.message_id == message.message_id).first()
            popup_html = generate_popup_post_html(message)
            message_edit.popup_html = popup_html

            if message.hide:
                popup_moderate = generate_popup_post_html(message, moderating=True)
                message_edit.popup_moderate = popup_moderate
                ret_str += popup_moderate
            else:
                ret_str += popup_html

            if message.regenerate_popup_html:
                message_edit.regenerate_popup_html = False
            message_edit.save()

        ret_str += '</div></a>'
    except:
        logger.exception("Could not generate popup html")
        ret_str = link_str

    return ret_str


def generate_popup_post_html(message, moderating=False):
    file_order, attach, number_files = attachment_info(message.message_id)
    ret_str = ''

    if message_has_images(message) and not message.hide:
        for i, file_name in enumerate(file_order, 1):
            if (file_name and
                    file_name in attach and
                    attach[file_name]["extension"] in config.FILE_EXTENSIONS_IMAGE):

                if ("height" not in attach[file_name] or "width" not in attach[file_name] or
                        not attach[file_name]["height"] or not attach[file_name]["width"]):
                    continue

                # Calculate height/width
                width = 200
                height = 200
                if attach[file_name]["width"] <= 200 and attach[file_name]["height"] <= 200:
                    width = attach[file_name]["width"]
                    height = attach[file_name]["height"]
                elif attach[file_name]["width"] > 200 or attach[file_name]["height"] > 200:
                    w_to_h_ratio = attach[file_name]["width"] / attach[file_name]["height"]
                    if attach[file_name]["width"] > attach[file_name]["height"]:
                        height = 200 / w_to_h_ratio
                    elif attach[file_name]["height"] > attach[file_name]["width"]:
                        width = w_to_h_ratio * 200

                ret_str += '<div class="reply-attach" ' \
                           f'style="width: {width}px; height: {height}px; ' \
                           f'background-image: url(\'/files/thumb/{message.message_id}/{quote(file_name)}\');"></div>'
        ret_str += '<div class="reply-break"></div>'

    ret_str += f'<div class="reply-text themed">{generate_popup_post_body_message(message, moderating=moderating)}</div>'

    return ret_str


def generate_popup_post_header(message, external_thread=False):
    """Generate header of message for reply link hover popup"""
    if not message:
        return "Error: No post found"

    str_return = ''
    try:
        if message.is_op or external_thread:
            subject = ''
            if message.is_op and external_thread:
                subject += '<span class="themed bold">[OP]</span>&nbsp;'

            if message.message_steg != "{}":
                subject += '<span class="themed bold">[Steg]</span>&nbsp;'

            if len(message.thread.subject) > 60:
                subject += f'{message.thread.subject[0:57]}...'
            else:
                subject += message.thread.subject
            str_return += f'<span class="themed reply-subject bold">{subject}</span>'

        str_return += f'&nbsp;<img style="position: relative; width: 15px; height: 15px" src="/icon/{message.address_from}">'

        access = get_access(message.thread.chan.address)
        identities = daemon_com.get_identities()
        address_style = ""
        if message.address_from == config.BITCHAN_DEVELOPER_ADDRESS:
            address_style = "font-family: 'Lucida Console', Monaco, monospace; color: purple; background-color: white;"
        elif message.address_from in access["primary_addresses"]:
            address_style = "font-family: 'Lucida Console', Monaco, monospace; color: red; background-color: white;"
        elif message.address_from in access["secondary_addresses"]:
            address_style = "font-family: 'Lucida Console', Monaco, monospace; color: orange; background-color: white;"
        elif message.address_from in identities:
            address_style = "font-family: 'Lucida Console', Monaco, monospace; color: #047841; background-color: white;"

        str_return += f'&nbsp;<span class="poster bold" style="{address_style}">{get_user_name(message.address_from, message.thread.chan.address)}</span>'

        nations_dict = dict(nations)
        if message.nation and message.nation in nations_dict:
            str_return += '&nbsp;<img style="position: relative;"'
            if nations_dict and message.nation in nations_dict:
                str_return += f' title="{nations_dict[message.nation]}"'
            str_return += f' src="/static/nations/{message.nation}">'

        elif message.nation_base64 and message.nation_name:
            str_return += f'&nbsp;<img style="position: relative; top: 3px; width: 25; height: 15" title="{message.nation_name}" src="/custom_flag_by_post_id/{message.message_id}">'

        str_return += f"&nbsp;{timestamp_to_date(message.timestamp_sent)}&nbsp;<span class='link'>{message.post_id}</span>"

        # Sage
        if message.sage:
            str_return += '&nbsp;<img style="position: relative; height: 15px" title="Sage" src="/static/leaf.png">'

        # Sticky
        if message.is_op and message.thread:
            sticky_local = False
            sticky_remote = False
            if message.thread.stickied_local:
                sticky_local = True
            with session_scope(config.DB_PATH) as new_session:
                admin_cmd = new_session.query(Command).filter(and_(
                    Command.action == "set",
                    Command.action_type == "thread_options",
                    Command.thread_id == message.thread.thread_hash)).first()
                if admin_cmd:
                    sticky_remote = admin_cmd.thread_sticky
            if sticky_local or sticky_remote:
                str_return += '&nbsp;<img style="position: relative; height: 15px" title="Sticky" src="/static/'
                if sticky_local and not sticky_remote:
                    str_return += 'pin_green.png'
                elif not sticky_local and sticky_remote:
                    str_return += 'pin_red.png'
                else:
                    str_return += 'pin_green_red.png'
                str_return += '">'

            # Lock
            locked_local = False
            locked_remote = False
            if message.thread.locked_local:
                locked_local = True
            with session_scope(config.DB_PATH) as new_session:
                admin_cmd = new_session.query(Command).filter(and_(
                    Command.action == "set",
                    Command.action_type == "thread_options",
                    Command.thread_id == message.thread.thread_hash)).first()
                if admin_cmd:
                    locked_remote = admin_cmd.thread_lock
            if locked_local or locked_remote:
                str_return += '&nbsp;<img style="position: relative; height: 15px" title="Locked" src="/static/'
                if locked_local and not locked_remote:
                    str_return += 'lock_green.png'
                elif not locked_local and locked_remote:
                    str_return += 'lock_red.png'
                else:
                    str_return += 'lock_green_red.png'
                str_return += '">'

            # Anchor
            anchored_local = False
            anchored_remote = False
            if message.thread.anchored_local:
                anchored_local = True
            with session_scope(config.DB_PATH) as new_session:
                admin_cmd = new_session.query(Command).filter(and_(
                    Command.action == "set",
                    Command.action_type == "thread_options",
                    Command.thread_id == message.thread.thread_hash)).first()
                if admin_cmd:
                    anchored_remote = admin_cmd.thread_anchor
            if anchored_local or anchored_remote:
                str_return += '&nbsp;<img style="position: relative; height: 15px" title="Anchored" src="/static/'
                if anchored_local and not anchored_remote:
                    str_return += 'anchor_green.png'
                elif not anchored_local and anchored_remote:
                    str_return += 'anchor_red.png'
                else:
                    str_return += 'anchor_green_red.png'
                str_return += '">'

    except Exception as err:
        logger.exception(f"Error in generate_popup_post_header(): {err}")
        str_return = "Error: Could not parse post header"

    return str_return


def generate_popup_post_body_file_info(message):
    ret_str = ""
    if message.file_amount:
        ret_str += f'<div class="reply-header link">{message.file_amount} File'
        if message.file_amount > 1:
            ret_str += "s"

        if message.file_size:
            ret_str += " ({}): ".format(human_readable_size(message.file_size))

        file_order, attach, number_files = attachment_info(message.message_id)
        for i, file_name in enumerate(file_order):
            if file_name:
                if len(file_name) > 25:
                    file_name = f"{file_name[:19]}...{file_name[-3:]}"
                else:
                    file_name = file_name
                ret_str += f" {file_name}"
                if i + 1 < message.file_amount:
                    ret_str += ","

        ret_str += '</div><div class="reply-break"></div>'
    return ret_str


def generate_popup_post_body_message(message, moderating=False):
    """Generate body of message for reply link hover popup"""
    if not message:
        return "Error: No post found"

    try:
        if not message.message:
            str_return = '<blockquote class="post">[No Text]</blockquote>'
        else:
            if message.hide and not moderating:
                msg_gen = '<span class="god-text">[moderated: hidden]</span>'
            elif message.delete_comment and not moderating:
                msg_gen = message.delete_comment
            else:
                msg_gen = message.message

            is_truncated, truncated_str = truncate(
                msg_gen,
                900,
                target_lines=config.BOARD_MAX_LINES)
            tr_str = truncated_str.rstrip().replace("\n", " ")
            str_return = f'<blockquote class="post">{tr_str}'
            if is_truncated:
                if len(msg_gen) > 900:
                    str_return += f'<br/>... [message truncated]'
                else:
                    str_return += f'<br/>...'
            str_return += '</blockquote>'

            # Remove all hyperlinks
            soup = BeautifulSoup(str_return, features="html.parser")
            for remove_a in soup.findAll('a'):
                remove_a.replaceWithChildren()
            str_return = str(soup)

            # Remove all scripts
            soup = BeautifulSoup(str_return, features="html.parser")
            for remove_script in soup.findAll('script'):
                remove_script.extract()
            str_return = str(soup)
    except Exception as err:
        logger.exception(f"{message.message_id[-config.ID_LENGTH:].upper()}: Error in generate_popup_post_body_message(): {err}")

        try:
            is_truncated, truncated_str = truncate(
                message.original_message,
                900,
                target_lines=config.BOARD_MAX_LINES)
            tr_str = truncated_str.rstrip().replace("\n", " ")
            str_return = f'<blockquote class="post">{tr_str}'
            if is_truncated:
                if len(msg_gen) > 900:
                    str_return += f'<br/>... [message truncated]'
                else:
                    str_return += f'<br/>...'
            str_return += '</blockquote>'
        except:
            logger.exception("Error attempting to generate popup of original message")
            str_return = "Error: Could not parse original message"

    return str_return


def attachment_info(message_id):
    attach_info = {}
    with session_scope(config.DB_PATH) as new_session:
        number_files = 0
        message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()
        if not message:
            return [], {}, 0

        try:
            media_info = json.loads(message.media_info)
        except:
            media_info = {}

        try:
            file_order = json.loads(message.file_order)
        except:
            file_order = []

        if not file_order:
            file_order = []

        if not os.path.exists(os.path.join(config.FILE_DIRECTORY, message_id)):
            # Files haven't been downloaded, only return file names and count
            file_count = 0
            for filename in file_order:
                if filename:
                    file_count += 1
            return file_order, {}, file_count

        for i, each_file in enumerate(file_order, start=1):
            number_files += 1
            if each_file in media_info:
                media_info[each_file]["file_number"] = i
                if i == 1:
                    media_info[each_file]["spoiler"] = message.image1_spoiler
                elif i == 2:
                    media_info[each_file]["spoiler"] = message.image2_spoiler
                elif i == 3:
                    media_info[each_file]["spoiler"] = message.image3_spoiler
                elif i == 4:
                    media_info[each_file]["spoiler"] = message.image4_spoiler

                attach_info[each_file] = media_info[each_file]

                # escape any exif data
                if 'exif' in attach_info[each_file]:
                    new_list = []
                    for each_exif in attach_info[each_file]['exif']:
                        try:
                            new_list.append(html.escape(each_exif))
                        except:
                            logger.exception(f"Couldn't escape string: {each_exif}")
                    attach_info[each_file]['exif'] = new_list

                # Calculate width and height percentages to determine thumbnail dimensions
                if "thumb_percent_height" not in attach_info[each_file]:
                    height = None
                    width = None
                    attach_info[each_file]["thumb_percent_height"] = 100
                    if "height" in media_info[each_file]:
                        height = media_info[each_file]["height"]
                    if "width" in media_info[each_file]:
                        width = media_info[each_file]["width"]

                    if height and width and height < width:
                        attach_info[each_file]["thumb_percent_height"] = height / width

        return file_order, attach_info, number_files


def get_user_name(address_from, address_to, full_address=False):
    username = "Anonymous"
    if address_to == address_from:
        return username

    identities = daemon_com.get_identities()
    address_book = daemon_com.get_address_book()
    chans = daemon_com.get_all_chans()

    if full_address:
        address = address_from
    else:
        address = address_from[-config.ID_LENGTH:]

    if address_from in identities:
        if identities[address_from]["label_short"]:
            username = f'{address} (You, {identities[address_from]["label_short"]})'
        else:
            username = f"{address} (You)"
    elif address_from in address_book:
        if address_book[address_from]["label_short"]:
            username = f'{address} ({address_book[address_from]["label_short"]})'
        else:
            username = f"{address} (ⒶⓃⓄⓃ)"
    elif address_from in chans:
        if chans[address_from]["label_short"]:
            username = f'{address} ({chans[address_from]["label_short"]})'
        else:
            username = f"{address} (ⒶⓃⓄⓃ)"
    else:
        username = address

    return username


def message_has_images(message):
    if not message:
        return None

    try:
        media_info = json.loads(message.media_info)
    except:
        media_info = {}

    try:
        file_order = json.loads(message.file_order)
    except:
        file_order = []

    for each_attachment in file_order:
        if (each_attachment in media_info and
                "extension" in media_info[each_attachment] and
                media_info[each_attachment]["extension"] in config.FILE_EXTENSIONS_IMAGE):
            return True

    return None

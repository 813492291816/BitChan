import datetime
import html
import json
import logging
import os
import time
from collections import OrderedDict
from operator import getitem
from urllib.parse import urlparse

from sqlalchemy import and_

import config
from bitchan_flask import nexus
from database.models import Chan
from database.models import Command
from database.models import Flags
from database.models import GlobalSettings
from database.models import Identity
from database.models import Messages
from forms.nations import nations
from utils import themes
from utils.files import human_readable_size
from utils.general import process_passphrase
from utils.replacements import format_body
from utils.replacements import replace_lt_gt
from utils.shared import get_combined_access

logger = logging.getLogger('bitchan.routes')


def attachment_info(message_id):
    dir = "{}/{}".format(config.FILE_DIRECTORY, message_id)
    number_files = 0
    if os.path.exists(dir):
        attachment_info = {}
        message = Messages.query.filter(Messages.message_id == message_id).first()
        if message:
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
                for each_attachment in os.listdir(dir):
                    file_order.append(each_attachment)

            for i, each_file in enumerate(file_order, start=1):
                for each_attachment in os.listdir(dir):
                    if each_attachment == each_file:
                        number_files += 1
                        if each_attachment in media_info:
                            if i == 1:
                                media_info[each_attachment]["spoiler"] = message.image1_spoiler
                            elif i == 2:
                                media_info[each_attachment]["spoiler"] = message.image2_spoiler
                            elif i == 3:
                                media_info[each_attachment]["spoiler"] = message.image3_spoiler
                            elif i == 4:
                                media_info[each_attachment]["spoiler"] = message.image4_spoiler
                            attachment_info[each_attachment] = media_info[each_attachment]

                # Find any stragglers
                for each_attachment in os.listdir(dir):
                    if each_attachment not in attachment_info:
                        attachment_info[each_attachment] = {
                            "height": None,
                            "width": None,
                            "size": None,
                            "extension": None,
                            "spoiler": None
                        }

            return file_order, attachment_info, number_files
    else:
        return [], {}, 0


def format_message_steg(message_id):
    message = Messages.query.filter(Messages.message_id == message_id).first()
    if message:
        try:
            message_steg = json.loads(message.message_steg)
        except:
            message_steg = {}
        msg_text = ""
        if message_steg:
            for i, (filename, each_msg) in enumerate(message_steg.items()):
                if i < len(message_steg) - 1:
                    msg_text += '<div style="padding-bottom: 1em"><span class="replace-funcs">File: {file}</span>' \
                                '<br/>{steg}</div>'.format(file=filename, steg=each_msg)
                else:
                    msg_text += '<div><span class="replace-funcs">File: {file}</span>' \
                                '<br/>{steg}</div>'.format(file=filename, steg=each_msg)
            return msg_text


def post_has_image(message_id):
    message = Messages.query.filter(Messages.message_id == message_id).first()
    if message:
        try:
            media_info = json.loads(message.media_info)
        except:
            media_info = {}
        for filename, info in media_info.items():
            if info["extension"] in config.FILE_EXTENSIONS_IMAGE:
                return True


def get_access(address):
    access = {}
    chan = Chan.query.filter(Chan.address == address).first()
    if chan:
        admin_cmd = Command.query.filter(and_(
            Command.action == "set",
            Command.action_type == "options",
            Command.chan_address == chan.address)).first()
        return get_combined_access(admin_cmd, chan)
    return access


def timestamp_to_date(timestamp):
    return datetime.datetime.fromtimestamp(
        timestamp).strftime('%d %b %Y (%a) %H:%M:%S')


def post_id(message_id):
    return message_id[-config.ID_LENGTH:].upper()


def get_user_name(address_from, address_to):
    username = "Anonymous"
    if address_to != address_from:
        if address_from in nexus.get_identities():
            if nexus.get_identities()[address_from]["label_short"]:
                username = "{id} (You, {lbl})".format(
                    id=address_from[-config.ID_LENGTH:],
                    lbl=nexus.get_identities()[address_from]["label_short"])
            else:
                username = "{} (You)".format(
                    address_from[-config.ID_LENGTH:])
        elif address_from in nexus.get_address_book():
            if nexus.get_address_book()[address_from]["label_short"]:
                username = "{id} ({lbl})".format(
                    id=address_from[-config.ID_LENGTH:],
                    lbl=nexus.get_address_book()[address_from]["label_short"])
            else:
                username = "{} (ⒶⓃⓄⓃ)".format(
                    address_from[-config.ID_LENGTH:])
        elif address_from in nexus.get_all_chans():
            if nexus.get_all_chans()[address_from]["label_short"]:
                username = "{id} ({lbl})".format(
                    id=address_from[-config.ID_LENGTH:],
                    lbl=nexus.get_all_chans()[address_from]["label_short"])
            else:
                username = "{} (ⒶⓃⓄⓃ)".format(
                    address_from[-config.ID_LENGTH:])
        else:
            username = address_from[-config.ID_LENGTH:]
    return username


def page_dict():
    command_options = {}
    unread_mail = 0

    admin_cmd = Command.query.filter(and_(
        Command.action == "set",
        Command.action_type == "options")).all()
    for each_cmd in admin_cmd:
        if each_cmd.chan_address and each_cmd.options:
            command_options[each_cmd.chan_address] = json.loads(each_cmd.options)

    for ident in Identity.query.all():
        if ident.unread_messages:
            unread_mail += ident.unread_messages

    chans_board_info = nexus.get_chans_board_info()
    chans_list_info = nexus.get_chans_list_info()

    address_book = OrderedDict(
        sorted(nexus._address_book_dict.items(), key=lambda x: getitem(x[1], 'label')))

    address_labels = nexus.get_address_labels()

    custom_flags = Flags.query.all()

    return dict(and_=and_,
                address_book=address_book,
                address_labels=address_labels,
                all_chans=nexus.get_all_chans(),
                attachment_info=attachment_info,
                bitmessage=nexus,
                chans_board_info=chans_board_info,
                chans_list_info=chans_list_info,
                command_options=command_options,
                config=config,
                custom_flags=custom_flags,
                format_body=format_body,
                format_message_steg=format_message_steg,
                get_access=get_access,
                get_user_name=get_user_name,
                html=html,
                human_readable_size=human_readable_size,
                identities=nexus.get_identities(),
                json=json,
                nations=dict(nations),
                post_has_image=post_has_image,
                post_id=post_id,
                process_passphrase=process_passphrase,
                replace_lt_gt=replace_lt_gt,
                settings=GlobalSettings.query.first(),
                themes=themes.themes,
                time=time,
                timestamp_to_date=timestamp_to_date,
                unread_mail=unread_mail,
                urlparse=urlparse)

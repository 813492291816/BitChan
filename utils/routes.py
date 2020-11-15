import datetime
import html
import json
import logging
import time
from collections import OrderedDict
from operator import getitem

from sqlalchemy import and_

import config
from bitchan_flask import nexus
from database.models import Chan
from database.models import Command
from database.models import GlobalSettings
from forms.nations import nations
from utils import themes
from utils.files import human_readable_size
from utils.general import process_passphrase
from utils.replacements import format_body
from utils.shared import get_combined_access

logger = logging.getLogger('bitchan.utils.routes')


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


def replace_lt_gt(s):
    s = s.replace("<", "&lt;")
    s = s.replace(">", "&gt;")
    return s


def page_dict():
    command_options = {}
    admin_cmd = Command.query.filter(and_(
        Command.action == "set",
        Command.action_type == "options")).all()
    for each_cmd in admin_cmd:
        if each_cmd.chan_address and each_cmd.options:
            command_options[each_cmd.chan_address] = json.loads(each_cmd.options)

    chans_board_unsorted = {}
    for each_chan in nexus.get_board_chans():
        chan = Chan.query.filter(and_(
            Chan.address == each_chan,
            Chan.type == "board")).first()
        if chan:
            chans_board_unsorted[each_chan] = {}
            chans_board_unsorted[each_chan]["db"] = chan
            chans_board_unsorted[each_chan]["bm_label"] = nexus.get_board_chans()[each_chan]
            chans_board_unsorted[each_chan]["label"] = html.escape(chan.label)
            chans_board_unsorted[each_chan]["description"] = replace_lt_gt(chan.description)
            chans_board_unsorted[each_chan]["rules"] = json.loads(chan.rules)

            access = get_access(chan.address)
            chans_board_unsorted[each_chan]["primary_addresses"] = access["primary_addresses"]
            chans_board_unsorted[each_chan]["secondary_addresses"] = access["secondary_addresses"]
            chans_board_unsorted[each_chan]["tertiary_addresses"] = access["tertiary_addresses"]
            chans_board_unsorted[each_chan]["restricted_addresses"] = access["restricted_addresses"]

            if len(chan.label) > config.LABEL_LENGTH:
                chans_board_unsorted[each_chan]["label_short"] = html.escape(chan.label[:config.LABEL_LENGTH])
            else:
                chans_board_unsorted[each_chan]["label_short"] = html.escape(chan.label)
    chans_board_info = OrderedDict(
        sorted(chans_board_unsorted.items(), key=lambda x: getitem(x[1], 'label')))

    chans_list_unsorted = {}
    for each_chan in nexus.get_list_chans():
        chan = Chan.query.filter(and_(
            Chan.address == each_chan,
            Chan.type == "list")).first()
        if chan:
            chans_list_unsorted[each_chan] = {}
            chans_list_unsorted[each_chan]["db"] = chan
            chans_list_unsorted[each_chan]["bm_label"] = nexus.get_list_chans()[each_chan]
            chans_list_unsorted[each_chan]["label"] = html.escape(chan.label)
            chans_list_unsorted[each_chan]["description"] = html.escape(chan.description)
            chans_list_unsorted[each_chan]["rules"] = json.loads(chan.rules)
            chans_list_unsorted[each_chan]["primary_addresses"] = json.loads(chan.primary_addresses)

            access = get_access(chan.address)
            chans_list_unsorted[each_chan]["primary_addresses"] = access["primary_addresses"]
            chans_list_unsorted[each_chan]["secondary_addresses"] = access["secondary_addresses"]
            chans_list_unsorted[each_chan]["tertiary_addresses"] = access["tertiary_addresses"]
            chans_list_unsorted[each_chan]["restricted_addresses"] = access["restricted_addresses"]

            if len(chan.label) > config.LABEL_LENGTH:
                chans_list_unsorted[each_chan]["label_short"] = html.escape(chan.label[:config.LABEL_LENGTH])
            else:
                chans_list_unsorted[each_chan]["label_short"] = html.escape(chan.label)
    chans_list_info = OrderedDict(
        sorted(chans_list_unsorted.items(), key=lambda x: getitem(x[1], 'label')))

    address_book = OrderedDict(
        sorted(nexus._address_book_dict.items(), key=lambda x: getitem(x[1], 'label')))

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

    address_labels = {}
    list_name_objects = [nexus.get_address_book(),
                         nexus.get_all_chans(),
                         nexus.get_identities()]
    for each_name_repo in list_name_objects:
        for each_address in each_name_repo:
            if "label_short" in each_name_repo[each_address]:
                address_labels[each_address] = each_name_repo[each_address]["label_short"]

    return dict(and_=and_,
                address_book=address_book,
                address_labels=address_labels,
                all_chans=nexus.get_all_chans(),
                bitmessage=nexus,
                chans_board_info=chans_board_info,
                chans_list_info=chans_list_info,
                command_options=command_options,
                config=config,
                format_body=format_body,
                get_access=get_access,
                get_user_name=get_user_name,
                html=html,
                human_readable_size=human_readable_size,
                identities=nexus.get_identities(),
                json=json,
                nations=dict(nations),
                post_id=post_id,
                process_passphrase=process_passphrase,
                replace_lt_gt=replace_lt_gt,
                settings=GlobalSettings.query.first(),
                themes=themes.themes,
                time=time,
                timestamp_to_date=timestamp_to_date)

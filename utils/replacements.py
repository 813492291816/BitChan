import base64
import html
import json
import logging
import re
import uuid
from urllib import parse

from sqlalchemy import and_

import config
from bitchan_client import DaemonCom
from config import DB_PATH
from database.models import AddressBook
from database.models import Chan
from database.models import Identity
from database.models import Messages
from database.models import StringReplace
from database.models import Threads
from database.utils import db_return
from database.utils import session_scope
from utils import replacements_simple
from utils.general import get_random_alphanumeric_string
from utils.general import process_passphrase
from utils.generate_popup import generate_reply_link_and_popup_html
from utils.gpg import gpg_process_texts
from utils.shared import regenerate_card_popup_post_html

logger = logging.getLogger("bitchan.replacements")
daemon_com = DaemonCom()


def format_body(message_id, body, truncate, is_board_view, preview=False, this_thread_hash=None, gpg_texts=None):
    """
    Formatting of post body text at time of page render
    Mostly to allow links to properly form after initial message processing from bitmessage
    """
    if not body:
        return ""

    split = False

    this_message = Messages.query.filter(
        Messages.message_id == message_id).first()

    if this_thread_hash:
        this_thread = Threads.query.filter(
            Threads.thread_hash == this_thread_hash).first()
        if not this_thread:
            this_thread = None
    elif this_message and this_message.thread:
        this_thread = this_message.thread
    else:
        this_thread = None

    if gpg_texts:
        pass
    elif this_message:
        try:
            gpg_texts = json.loads(this_message.gpg_texts)
        except:
            gpg_texts = {}

    if gpg_texts and body:
        body = gpg_process_texts(body, gpg_texts)

    lines = body.split("<br/>")

    if ((truncate and len(lines) > config.BOARD_MAX_LINES) or
            (truncate and len(body) > config.BOARD_MAX_CHARACTERS)):
        split = True

    if split:
        lines = lines[:config.BOARD_MAX_LINES]

    total_popups = 0

    regex_passphrase = r"""(\[\"(private|public)\"\,\s\"(board|list)\"\,\s\".{1,25}?\"\,\s\".{1,128}?\"\,\s\[(\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\[(\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\[(\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\[((\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\{(.*?)(\})|(\}\}))\,\s\"(.*?)\"\])"""
    regex_passphrase_base64_link = r"""http\:\/\/(172\.28\.1\.1|\blocalhost\b)\:8000\/join_base64\/([A-Za-z0-9+&]+={0,2})(\s|\Z)"""
    regex_address = r'(\[identity\](BM\-[a-zA-Z0-9]{32,34})\[\/identity\])'

    # Used to store multi-line strings to replace >>> crosspost text.
    # Needs to occur at end after all crossposts have been found.
    dict_replacements = {}

    for line in range(len(lines)):
        # Search and append identity addresses with useful links
        number_finds = len(re.findall(regex_address, html.unescape(lines[line])))
        for i in range(number_finds):
            each_find = re.search(regex_address, html.unescape(lines[line]))
            to_replace = each_find.groups()[0]
            address = each_find.groups()[1]

            identity = Identity.query.filter(
                Identity.address == address).first()
            address_book = AddressBook.query.filter(
                AddressBook.address == address).first()

            replaced_code = """<img style="width: 15px; height: 15px; position: relative; top: 3px;" src="/icon/{0}"> <span class="replace-funcs">{0}</span> (<button type="button" class="btn" title="Copy to Clipboard" onclick="CopyToClipboard('{0}')">&#128203;</button>""".format(address)

            if identity:
                replaced_code += ' <span class="replace-funcs">You, {}</span>'.format(
                                    identity.label)
            elif address_book:
                replaced_code += ' <span class="replace-funcs">{},</span>' \
                                 ' <a class="link" href="/compose/0/{}">Send Message</a>'.format(
                                    address_book.label, address)
            else:
                replaced_code += ' <a class="link" href="/compose/0/{0}">Send Message</a>,' \
                                 ' <a class="link" href="/address_book_add/{0}">Add to Address Book</a>'.format(
                                    address)
            replaced_code += ')'

            lines[line] = lines[line].replace(to_replace, replaced_code, 1)

        # Search and replace Board/List Passphrase with link
        number_finds = len(re.findall(regex_passphrase, html.unescape(lines[line])))
        for i in range(number_finds):
            url = None
            each_find = re.search(regex_passphrase, html.unescape(lines[line]))
            passphrase = each_find.groups()[0]
            passphrase_escaped = html.escape(passphrase)

            # Find if passphrase already exists (already joined board/list)
            chan = Chan.query.filter(Chan.passphrase == passphrase).first()
            if chan:
                link_text = ""
                if chan.access == "public":
                    link_text += "Public "
                elif chan.access == "private":
                    link_text += "Private "
                if chan.type == "board":
                    link_text += "Board "
                elif chan.type == "list":
                    link_text += "List "
                link_text += "/{}/".format(chan.label)
                if chan.type == "board":
                    url = '<a class="link" href="/board/{a}/1" title="{d}">{l}</a>'.format(
                        a=chan.address, d=chan.description, l=link_text)
                elif chan.type == "list":
                    url = '<a class="link" href="/list/{a}" title="{d}">{l}</a>'.format(
                        a=chan.address, d=chan.description, l=link_text)
            else:
                errors, pass_info = process_passphrase(passphrase)
                if errors:
                    continue
                link_text = ""
                if pass_info["access"] == "public":
                    link_text += "Public "
                elif pass_info["access"] == "private":
                    link_text += "Private "
                if pass_info["type"] == "board":
                    link_text += "Board "
                elif pass_info["type"] == "list":
                    link_text += "List "
                link_text += "/{}/".format(pass_info["label"])
                url = """<a class="link" href="/join_base64/{p}" title="{d}">{l} (Click to Join)</a>""".format(
                    p=html.escape(base64.b64encode(passphrase.encode()).decode()),
                    d=pass_info["description"],
                    l=link_text)
            if url:
                lines[line] = lines[line].replace(passphrase_escaped, url, 1)

        # Search and replace Board/List Passphrase base64 links with friendlier link
        number_finds = len(re.findall(regex_passphrase_base64_link, html.unescape(lines[line])))
        for i in range(number_finds):
            url = None
            each_find = re.search(regex_passphrase_base64_link, html.unescape(lines[line]))

            link = each_find.group()
            if len(each_find.groups()) < 2:
                continue
            passphrase_encoded = html.unescape(each_find.groups()[1])
            passphrase_dict_json = base64.b64decode(passphrase_encoded).decode()
            passphrase_dict = json.loads(passphrase_dict_json)
            passphrase_decoded = passphrase_dict["passphrase"]

            # Find if passphrase already exists (already joined board/list)
            chan = Chan.query.filter(Chan.passphrase == passphrase_decoded).first()
            if chan:
                link_text = ""
                if chan.access == "public":
                    link_text += "Public "
                elif chan.access == "private":
                    link_text += "Private "
                if chan.type == "board":
                    link_text += "Board "
                elif chan.type == "list":
                    link_text += "List "
                link_text += "/{}/".format(chan.label)
                if chan.type == "board":
                    url = '<a class="link" href="/board/{a}/1" title="{d}">{l}</a>'.format(
                        a=chan.address, d=chan.description, l=link_text)
                elif chan.type == "list":
                    url = '<a class="link" href="/list/{a}" title="{d}">{l}</a>'.format(
                        a=chan.address, d=chan.description, l=link_text)
            else:
                errors, pass_info = process_passphrase(passphrase_decoded)
                if errors:
                    logger.error("Errors parsing passphrase: {}".format(errors))
                    continue
                link_text = ""
                if pass_info["access"] == "public":
                    link_text += "Public "
                elif pass_info["access"] == "private":
                    link_text += "Private "
                if pass_info["type"] == "board":
                    link_text += "Board "
                elif pass_info["type"] == "list":
                    link_text += "List "
                link_text += "/{}/".format(pass_info["label"])
                url = """<a class="link" href="/join_base64/{p}" title="{d}">{l} (Click to Join)</a>""".format(
                    p=html.escape(passphrase_encoded),
                    d=pass_info["description"],
                    l=link_text)
            if url:
                lines[line] = lines[line].replace(link.strip(), url, 1)

        # Search and replace BM address with post ID with link
        for each_find in is_board_post_reply(lines[line]):
            each_string = each_find[0]
            each_address = each_find[1]
            total_popups += lines[line].count(each_string)
            if total_popups > 50:
                break

            board_address = each_address.split("/")[0]
            board_post_id = each_address.split("/")[1]
            chan_entry = db_return(Chan).filter(and_(
                Chan.type == "board",
                Chan.address == board_address)).first()
            if chan_entry:
                message = db_return(Messages).filter(
                    Messages.post_id == board_post_id).first()
                if message:
                    link_text = '&gt;&gt;&gt;/{l}/{p}'.format(
                        l=html.escape(chan_entry.label), p=message.post_id)
                    rep_str = generate_reply_link_and_popup_html(
                        message,
                        board_view=True,
                        external_thread=True,
                        external_board=True,
                        link_text=link_text)

                    # Store replacement in dict to conduct after all matches have been found
                    new_id = str(uuid.uuid4())
                    dict_replacements[new_id] = rep_str
                    lines[line] = lines[line].replace(each_string, new_id, 1)
                else:
                    description = chan_entry.description.replace('"', "&quot;")
                    lines[line] = lines[line].replace(
                        each_string,
                        f'<a class="link" href="/board/{each_address}/1" title="{description}">'
                        f'>>>/{html.escape(chan_entry.label)}/'
                        f'</a>{board_post_id}',
                        1)

        # Search and replace only BM address with link
        for each_find in is_chan_reply(lines[line]):
            each_string = each_find[0]
            each_address = each_find[1]
            chan_entry = db_return(Chan).filter(and_(
                Chan.type == "board",
                Chan.address == each_address)).first()
            list_entry = db_return(Chan).filter(and_(
                Chan.type == "list",
                Chan.address == each_address)).first()
            if chan_entry:
                lines[line] = lines[line].replace(
                    each_string,
                    '<a class="link" href="/board/{a}/1" title="{d}">>>>/{l}/</a>'.format(
                        a=each_address, d=chan_entry.description.replace('"', '&quot;'), l=html.escape(chan_entry.label)),
                    1)
            elif list_entry:
                lines[line] = lines[line].replace(
                    each_string,
                    '<a class="link" href="/list/{a}" title="{d}">>>>/{l}/</a>'.format(
                        a=each_address, d=list_entry.description, l=list_entry.label),
                    1)

        # Find and replace hyperlinks
        for each_word in lines[line].replace("\r", "").split(" "):
            for suff in [")?", "]?", ").", "].", "&gt;.", "&gt;?", ".", ")", "]", "&gt;", "?"]:
                if each_word.endswith(suff):
                    each_word = each_word[:-len(suff)]
                    break
            try:
                parsed = parse.urlparse(each_word)
                if parsed.scheme and parsed.netloc:
                    link = str(parsed.geturl()).replace("</span>", "")
                    link_id = str(uuid.uuid4())
                    dict_replacements[link_id] = f'<a class="link" href="{link}" target="_blank">{link}</a>'
                    lines[line] = lines[line].replace(link, link_id, 1)
            except:
                logger.exception(f'replace hyperlink: "{each_word}"')

        # Show dummy formatting/link
        if preview and not this_thread:
            for each_find in is_post_id_reply(lines[line]):
                total_popups += lines[line].count(each_find["string"])
                if total_popups > 50:
                    break

                # Determine if OP or identity/address book label is to be appended to reply post ID
                message = Messages.query.filter(
                    Messages.post_id == each_find["id"]).first()

                name_str = ""
                if message:
                    identity = Identity.query.filter(
                        Identity.address == message.address_from).first()
                    if not name_str and identity and identity.label:
                        name_str = " ({})".format(identity.label)
                    address_book = AddressBook.query.filter(
                        AddressBook.address == message.address_from).first()
                    if not name_str and address_book and address_book.label:
                        name_str = " ({})".format(address_book.label)

                ret_str = f'<a class="crosslink reply-tooltip under-solid" href="#previewurl">{each_find["string"]}{name_str}</a>'

                # Store replacement in dict to conduct after all matches have been found
                new_id = str(uuid.uuid4())
                dict_replacements[new_id] = ret_str
                lines[line] = lines[line].replace(each_find["string"], new_id, 1)

        # Search and replace Post Reply ID with link
        # Must come after replacement of hyperlinks
        for each_find in is_post_id_reply(lines[line]):
            if not this_thread:
                break

            rep_str = None
            total_popups += lines[line].count(each_find["string"])
            if total_popups > 50:
                break

            # Determine if OP or identity/address book label is to be appended to reply post ID
            message = Messages.query.filter(
                Messages.post_id == each_find["id"]).first()

            name_str = ""
            self_post = False
            if message:
                identity = Identity.query.filter(
                    Identity.address == message.address_from).first()
                if not name_str and identity and identity.label:
                    self_post = True
                    name_str = " ({})".format(identity.label)
                address_book = AddressBook.query.filter(
                    AddressBook.address == message.address_from).first()
                if not name_str and address_book and address_book.label:
                    name_str = " ({})".format(address_book.label)

            valid_ref = is_post_reference_valid(
                each_find["id"],
                each_find["location"],
                this_thread.thread_hash,
                this_thread.chan.address)

            if valid_ref:
                # Same-thread reference
                if (each_find["location"] == "local" and
                        message.thread.thread_hash == this_thread.thread_hash):
                    if message.thread.op_sha256_hash == message.message_sha256_hash:
                        name_str = " (OP)"
                    rep_str = generate_reply_link_and_popup_html(
                        message,
                        board_view=is_board_view,
                        self_post=self_post,
                        name_str=name_str)

                # Off-board cross-post
                elif (each_find["location"] == "remote" and
                        message.thread.thread_hash != this_thread.thread_hash and
                        message.thread.chan.address != this_thread.chan.address):
                    rep_str = generate_reply_link_and_popup_html(
                        message,
                        board_view=True,
                        self_post=self_post,
                        name_str=name_str,
                        external_thread=True,
                        external_board=True)

                # Off-thread cross-post
                elif (each_find["location"] == "remote" and
                        message.thread.thread_hash != this_thread.thread_hash):
                    rep_str = generate_reply_link_and_popup_html(
                        message,
                        board_view=True,
                        self_post=self_post,
                        name_str=name_str,
                        external_thread=True)

                if rep_str:
                    # Ensure post references are correct
                    if not preview and this_message.post_id not in message.post_ids_replying_to_msg:
                        try:
                            post_ids_replying_to_msg = json.loads(message.post_ids_replying_to_msg)
                        except:
                            post_ids_replying_to_msg = []

                        post_ids_replying_to_msg.append(this_message.post_id)
                        message.post_ids_replying_to_msg = json.dumps(post_ids_replying_to_msg)
                        message.save()

                        regenerate_card_popup_post_html(message_id=message.message_id)

                    # Store replacement in dict to conduct after all matches have been found
                    new_id = str(uuid.uuid4())
                    dict_replacements[new_id] = rep_str
                    lines[line] = lines[line].replace(each_find["string"], new_id, 1)

    return_body = "<br/>".join(lines)

    for id_to_replace, replace_with in dict_replacements.items():
        return_body = return_body.replace(id_to_replace, replace_with, 1)

    if split and this_thread:
        truncate_str = '<br/><br/><span class="expand">Comment truncated. ' \
                       '<a class="link" href="/thread/{ca}/{th}#{pid}">Click here</a>' \
                       ' to view the full post.</span>'.format(
            ca=this_thread.chan.address,
            th=this_thread.thread_hash_short,
            pid=this_message.post_id)
        return_body += truncate_str

    return return_body


def is_post_reference_valid(reply_id, location, msg_thread_hash, msg_chan_address):
    # Determine if OP or identity/address book label is to be appended to reply post ID
    with session_scope(DB_PATH) as new_session:
        message = new_session.query(
            Messages).filter(Messages.post_id == reply_id).first()

        # Same-thread reference
        if (location == "local" and
                message and
                message.thread and
                message.thread.thread_hash == msg_thread_hash):
            return True

        # Off-board cross-post
        elif (location == "remote" and
              message and
              message.thread and
              message.thread.thread_hash != msg_thread_hash and
              message.thread.chan.address != msg_chan_address):
            return True

        # Off-thread cross-post
        elif (location == "remote" and
              message and
              message.thread and
              message.thread.thread_hash != msg_thread_hash):
            return True

def replace_with_saved_replacements(message_id, body, address=None):
    try:
        with session_scope(DB_PATH) as new_session:
            message = new_session.query(Messages).filter(Messages.message_id == message_id).first()
            if not message and not address:
                return body

            if message and message.thread and message.thread.chan and message.thread.chan.address:
                address = message.thread.chan.address

            body = replace_strings(body, address)
    except:
        pass

    return body


def process_replacements(body, seed, message_id, address=None, steg=False, preview=False, force_replacements=False):
    """Replace portions of text for formatting and text generation purposes"""
    if not body:
        return body

    with session_scope(DB_PATH) as new_session:
        this_message = new_session.query(Messages).filter(
            Messages.message_id == message_id).first()

        if this_message and this_message.text_replacements and not steg and not force_replacements:
            return this_message.text_replacements

    body = replace_with_saved_replacements(message_id, body, address=address)

    # green/pink text processing Stage 1 of 2 (must be before all text style formatting)
    greenpink_replacements = replace_greenpink(body)
    if greenpink_replacements:
        # Replace ASCII text and tags with ID strings
        for each_greenpink_replace in greenpink_replacements:
            body = body.replace(each_greenpink_replace["string_with_tags"],
                                each_greenpink_replace["ID"], 1)

    # ASCII and [code] processing Stage 1 of 2 (must be before all text style formatting)
    ascii_replacements = replace_ascii(body)
    if ascii_replacements:
        # Replace ASCII text and tags with ID strings
        for each_ascii_replace in ascii_replacements:
            body = body.replace(each_ascii_replace["string_with_tags"],
                                each_ascii_replace["ID"], 1)

    ascii_replacements_small = replace_ascii_small(body)
    if ascii_replacements_small:
        # Replace ASCII text and tags with ID strings
        for each_ascii_replace in ascii_replacements_small:
            body = body.replace(each_ascii_replace["string_with_tags"],
                                each_ascii_replace["ID"], 1)

    ascii_replacements_xsmall = replace_ascii_xsmall(body)
    if ascii_replacements_xsmall:
        # Replace ASCII text and tags with ID strings
        for each_ascii_replace in ascii_replacements_xsmall:
            body = body.replace(each_ascii_replace["string_with_tags"],
                                each_ascii_replace["ID"], 1)

    code_replacements = replace_code(body)
    if code_replacements:
        # Replace [code] text and tags with ID strings
        for each_code_replace in code_replacements:
            body = body.replace(each_code_replace["string_with_tags"],
                                each_code_replace["ID"], 1)

    body = replace_colors(body)
    body = replace_candy(body)
    body = replace_rot(body)

    # Simple replacements
    body = replacements_simple.replace_8ball(body, seed)
    body = replacements_simple.replace_card_pulls(body, seed)
    body = replacements_simple.replace_dice_rolls(body, seed)
    body = replacements_simple.replace_flip_flop(body, seed)
    body = replacements_simple.replace_iching(body, seed)
    body = replacements_simple.replace_rock_paper_scissors(body, seed)
    body = replacements_simple.replace_rune_b_pulls(body, seed)
    body = replacements_simple.replace_rune_pulls(body, seed)
    body = replacements_simple.replace_tarot_c_pulls(body, seed)
    body = replacements_simple.replace_tarot_pulls(body, seed)

    try:  # these have the highest likelihood of unknown failure
        body = replacements_simple.replace_stich(body, seed, preview=preview)
        body = replacements_simple.replace_god_song(body, seed, message_id, preview=preview)
    except:
        logger.exception("stich or god_song exception")

    body = replace_pair(body, '<mark>', '</mark>', "``")
    body = replace_pair(body, '<sup style="font-size: smaller">', "</sup>", r"\^\^")
    body = replace_pair(body, '<sub style="font-size: smaller">', "</sub>", r"\%\%")
    body = replace_pair(body, '<span style="font-weight: bold">', '</span>', "@@")
    body = replace_pair(body, '<span style="font-style: italic">', "</span>", "~~")
    body = replace_pair(body, '<span style="text-decoration: underline">', '</span>', "__")
    body = replace_pair(body, '<span style="text-decoration: line-through">', '</span>', r"\+\+")
    body = replace_pair(body, '<span class="replace-small">', '</span>', r"\$\$")
    body = replace_pair(body, '<span class="replace-big">', '</span>', "##")
    body = replace_pair(body, '<span style="color:#F00000">', '</span>', r"\^r")
    body = replace_pair(body, '<span style="color:#57E8ED">', '</span>', r"\^b")
    body = replace_pair(body, '<span style="color:#FFA500">', '</span>', r"\^o")
    body = replace_pair(body, '<span style="color:#3F99CC">', '</span>', r"\^c")
    body = replace_pair(body, '<span style="color:#A248A5">', '</span>', r"\^p")
    body = replace_pair(body, '<span style="color:#B67C55">', '</span>', r"\^t")
    body = replace_pair(body, '<span class="replace-shadow">', '</span>', r"\^s")
    body = replace_pair(body, '<span class="replace-spoiler">', '</span>', r"\*\*")

    body = replace_regex(
        body,
        r"(?s)(?i)(\[meme\])(.*?)(\[\/meme\])",
        '<span style="background: linear-gradient(to right, red, orange, yellow, green, blue, indigo, violet); '
        '-webkit-background-clip: text; -webkit-text-fill-color: transparent;">',
        "</span>")
    body = replace_regex(
        body,
        r"(?s)(?i)(\[autism\])(.*?)(\[\/autism\])",
        '<span class="animated">',
        "</span>")
    body = replace_regex(
        body,
        r"(?s)(?i)(\[flash\])(.*?)(\[\/flash\])",
        '<span class="replace-blinking">',
        "</span>")
    body = replace_regex(
        body,
        r"(?s)(?i)(\[center\])(.*?)(\[\/center\])",
        '<div style="text-align: center;">',
        "</div>")
    body = replace_regex(
        body,
        r"(?s)(?i)(\[back\])(.*?)(\[\/back\])",
        '<bdo dir="rtl">',
        "</bdo>")
    body = replace_regex(
        body,
        r"(?s)(?i)(\[cap\])(.*?)(\[\/cap\])",
        '<span style="font-variant: small-caps;">',
        "</span>")
    body = replace_regex(
        body,
        r"(?s)(?i)(\[kern\])(.*?)(\[\/kern\])",
        '<span style="letter-spacing: 5px;">',
        "</span>")

    # Replacements with JS that need to come after text formatting replacements
    body = replacements_simple.replace_countdown(body)

    #
    # Code that needs to occur after text style formatting
    #

    # Convert newline characters to "<br/>"
    # This needs to occur before Stage 2 of ASCII processing
    body_lines = body.split("\n")
    body = "<br/>".join(body_lines)

    # ASCII processing Stage 2 of 2 (must be after all text formatting replacements)
    if ascii_replacements:
        # Replace ID strings with ASCII text and formatted tags
        for each_ascii_replace in ascii_replacements:
            str_final = '<div class="language-ascii-art">{}</div>'.format(
                each_ascii_replace["string_wo_tags"])
            body = body.replace(each_ascii_replace["ID"], str_final, 1)

    if ascii_replacements_small:
        # Replace ID strings with ASCII text and formatted tags
        for each_ascii_replace in ascii_replacements_small:
            str_final = '<div class="language-ascii-art-s">{}</div>'.format(
                each_ascii_replace["string_wo_tags"])
            body = body.replace(each_ascii_replace["ID"], str_final, 1)

    if ascii_replacements_xsmall:
        # Replace ID strings with ASCII text and formatted tags
        for each_ascii_replace in ascii_replacements_xsmall:
            str_final = '<div class="language-ascii-art-xs">{}</div>'.format(
                each_ascii_replace["string_wo_tags"])
            body = body.replace(each_ascii_replace["ID"], str_final, 1)

    if code_replacements:
        # Replace ID strings with [code] text and formatted tags
        for each_code_replace in code_replacements:
            str_final = '<div class="code">{}</div>'.format(
                each_code_replace["string_wo_tags"])
            body = body.replace(each_code_replace["ID"], str_final, 1)

    if greenpink_replacements:
        # Replace ID strings with green/pink text
        for each_greenpink_replace in greenpink_replacements:
            body = body.replace(each_greenpink_replace["ID"], each_greenpink_replace["string_wo_tags"], 1)

    if not steg:
        with session_scope(DB_PATH) as new_session:
            this_message = new_session.query(Messages).filter(
                Messages.message_id == message_id).first()
            if this_message:
                this_message.text_replacements = body
                new_session.commit()

    return body


def replace_lt_gt(s):
    if s is not None:
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
    return s


def is_post_id_reply(text):
    list_ids_strings = []
    list_strings_local = re.findall(r'(?<!&gt;)&gt;&gt;[A-Z0-9]{9}(?!\.\\.)', text)
    list_strings_remote = re.findall(r'&gt;&gt;&gt;[A-Z0-9]{9}(?!\.\\.)', text)
    for each_string in list_strings_local:
        try:
            list_ids_strings.append({
                "string": each_string,
                "id": each_string[-9:],
                "location": "local"
            })
        except:
            logger.exception("Match post ID")
    for each_string in list_strings_remote:
        try:
            list_ids_strings.append({
                "string": each_string,
                "id": each_string[-9:],
                "location": "remote"
            })
        except:
            logger.exception("Match post ID")
    return list_ids_strings


def is_board_post_reply(text):
    list_ids_strings = []
    list_strings = re.findall(r'&gt;&gt;&gt;BM-[a-zA-Z0-9]{34}\/[A-Z0-9]{9}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{33}\/[A-Z0-9]{9}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{32}\/[A-Z0-9]{9}', text)
    for each_string in list_strings:
        try:
            if len(each_string) == 59:
                list_ids_strings.append((each_string, each_string[-47:]))
            if len(each_string) == 58:
                list_ids_strings.append((each_string, each_string[-46:]))
            if len(each_string) == 57:
                list_ids_strings.append((each_string, each_string[-45:]))
        except:
            logger.exception("is_board_post_reply()")
    return list_ids_strings


def is_chan_reply(text):
    list_ids_strings = []
    list_strings = re.findall(r'&gt;&gt;&gt;BM-[a-zA-Z0-9]{34}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{33}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{32}', text)
    for each_string in list_strings:
        try:
            if len(each_string) == 49:
                list_ids_strings.append((each_string, each_string[-37:]))
            if len(each_string) == 48:
                list_ids_strings.append((each_string, each_string[-36:]))
            if len(each_string) == 47:
                list_ids_strings.append((each_string, each_string[-35:]))
        except:
            logger.exception("is_chan_reply()")
    return list_ids_strings


def eliminate_buddy(op_matches, cl_matches):
    """eliminate last match that doesn't have a buddy"""
    if len(op_matches) + len(cl_matches) % 2 != 0:
        if len(op_matches) > len(cl_matches):
            op_matches.pop()
        if len(cl_matches) > len(op_matches):
            cl_matches.pop()
    return op_matches, cl_matches


def replace_regex(body, regex, op, cl):
    matches = re.findall(regex, body)
    # print("matches = {}".format(matches))
    for i, match in enumerate(matches):
        if i > 50:
            break
        body = body.replace(
            "{0}{1}{2}".format(match[0], match[1], match[2]),
            '{}{}{}'.format(op, match[1], cl),
            1)
    return body


def replace_greenpink(text):
    if not text:
        return text

    list_replacements = []
    lines = text.split("\n")
    for line in range(len(lines)):
        # Search and replace pinktext
        if (len(lines[line]) > 1 and
                (lines[line].startswith("&lt;") and lines[line][4:8] != "&lt;")):
            list_replacements.append({
                "ID": get_random_alphanumeric_string(
                    30, with_punctuation=False, with_spaces=False),
                "string_with_tags": lines[line],
                "string_wo_tags": f'<span style="color: #E0727F">{lines[line]}</span>'
            })

        # Search and replace greentext
        if (len(lines[line]) > 1 and
                (lines[line].startswith("&gt;") and lines[line][4:8] != "&gt;")):
            list_replacements.append({
                "ID": get_random_alphanumeric_string(
                    30, with_punctuation=False, with_spaces=False),
                "string_with_tags": lines[line],
                "string_wo_tags": f'<span class="greentext">{lines[line]}</span>'
            })

    return list_replacements


def replace_ascii(text):
    if not text:
        return []
    list_replacements = []
    for each_find in re.finditer(r"(?s)(?i)\[aa](.*?)\[\/aa]", text):
        list_replacements.append({
            "ID": get_random_alphanumeric_string(
                30, with_punctuation=False, with_spaces=False),
            "string_with_tags": each_find.group(),
            "string_wo_tags": each_find.groups()[0]
        })
    return list_replacements


def replace_ascii_small(text):
    if not text:
        return []
    list_replacements = []
    for each_find in re.finditer(r"(?s)(?i)\[aa\-s](.*?)\[\/aa\-s]", text):
        list_replacements.append({
            "ID": get_random_alphanumeric_string(
                30, with_punctuation=False, with_spaces=False),
            "string_with_tags": each_find.group(),
            "string_wo_tags": each_find.groups()[0]
        })
    return list_replacements


def replace_ascii_xsmall(text):
    if not text:
        return []
    list_replacements = []
    for each_find in re.finditer(r"(?s)(?i)\[aa\-xs](.*?)\[\/aa\-xs]", text):
        list_replacements.append({
            "ID": get_random_alphanumeric_string(
                30, with_punctuation=False, with_spaces=False),
            "string_with_tags": each_find.group(),
            "string_wo_tags": each_find.groups()[0]
        })
    return list_replacements


def replace_code(text):
    if not text:
        return []
    list_replacements = []
    for each_find in re.finditer(r"(?s)(?i)\[code](.*?)\[\/code]", text):
        list_replacements.append({
            "ID": get_random_alphanumeric_string(
                30, with_punctuation=False, with_spaces=False),
            "string_with_tags": each_find.group(),
            "string_wo_tags": each_find.groups()[0]
        })
    return list_replacements


def replace_candy(body):
    open_tag_1 = '<span style="color: blue;">'
    open_tag_2 = '<span style="color: red;">'
    close_tag = '</span>'
    regex = r"(?i)\[\bcandy\b\](.*?)\[\/\bcandy\b\]"
    matches_full = re.finditer(regex, body)

    for each_find in matches_full:
        candied = ""
        for i, char_ in enumerate(each_find.groups()[0]):
            if re.findall(r"[\S]", char_):  # if non-whitespace char
                open_tag = open_tag_1 if i % 2 else open_tag_2
                candied += "{}{}{}".format(open_tag, char_, close_tag)
            else:
                candied += char_
        body = body.replace(each_find.group(), candied, 1)
    return body


def replace_colors(body):
    matches = re.findall(r"(?s)(?i)(\[color=\((\#[A-Fa-f0-9]{6}|\#[A-Fa-f0-9]{3})\)\])(.*?)(\[\/color\])", body)
    for i, match in enumerate(matches):
        if i > 50:
            break
        body = body.replace(
            "{0}{1}[/color]".format(match[0], match[2]),
            '<span style="color:{color};">{text}</span>'.format(color=match[1], text=match[2]),
            1)
    return body


def replace_rot(body):
    matches = re.findall(r"(?i)(\[rot=(360|3[0-5][0-9]{1}|[0-2]?[0-9]{1,2})])(.?){1}\[\/rot]", body)
    for i, match in enumerate(matches, 1):
        if i > 50:
            break
        body = body.replace(
            "{0}{1}[/rot]".format(match[0], match[2]),
            '<span style="transform: rotate({deg}deg); -webkit-transform: rotate({deg}deg); display: inline-block;">{char}</span>'.format(deg=match[1], char=match[2]),
            1)
    return body


def replace_pair(body, start_tag, end_tag, pair):
    reg_pair = "({})(.*?)({})".format(pair, pair)
    try:
        body = re.sub(reg_pair, start_tag + r'\g<2>' + end_tag, body)
    except Exception:
        logger.exception("replace pair")
    finally:
        return body


def replace_dict_keys_with_values(body, filter_dict):
    """replace keys with values from input dictionary"""
    for key, value in filter_dict.items():
        body = re.sub(r"\b{}\b".format(key), value, body)
    return body


def replace_strings(str_in, address=None):
    """process word replacements"""
    with session_scope(DB_PATH) as new_session:
        for each_rep in new_session.query(StringReplace).all():
            if each_rep.only_board_address and address and address not in each_rep.only_board_address:
                continue  # Skip boards not listed (if boards are listed)
            if each_rep.string and each_rep.string in str_in:
                str_in = str_in.replace(each_rep.string, each_rep.string_replacement)
            elif each_rep.regex:
                for each_find in re.findall(each_rep.regex, str_in):
                    str_in = str_in.replace(each_find, each_rep.string_replacement, 1)
        return str_in

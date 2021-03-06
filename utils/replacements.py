import base64
import html
import json
import logging
import re
from urllib import parse

from sqlalchemy import and_

from config import DATABASE_BITCHAN
from database.models import AddressBook
from database.models import Chan
from database.models import Identity
from database.models import Messages
from database.models import Threads
from database.utils import db_return
from utils import replacements_simple
from utils.general import get_random_alphanumeric_string
from utils.general import pairs
from utils.general import process_passphrase

DB_PATH = 'sqlite:///' + DATABASE_BITCHAN

logger = logging.getLogger("bitchan.replacements")


def replace_lt_gt(s):
    if s is not None:
        s = s.replace("<", "&lt;")
        s = s.replace(">", "&gt;")
    return s


def is_post_id_reply(text):
    dict_ids_strings = {}
    list_strings = re.findall(r'(?<!\S)&gt;&gt;[A-Z0-9]{9}(?!\S)', text)
    for each_string in list_strings:
        dict_ids_strings[each_string] = each_string[-9:]
    for each_string, each_id in dict_ids_strings.items():
        try:
            post_id = int(each_id, 16)
        except Exception as e:
            logger.exception("Not a post reply: {}".format(text))
    return dict_ids_strings


def isChanThreadReply(text):
    dict_ids_strings = {}
    list_strings = re.findall(r'(?<!\S)&gt;&gt;&gt;BM-[a-zA-Z0-9]{34}\/[A-Z0-9]{9}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{33}\/[A-Z0-9]{9}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{32}\/[A-Z0-9]{9}', text)
    for each_string in list_strings:
        if len(each_string) == 59:
            dict_ids_strings[each_string] = each_string[-47:]
        if len(each_string) == 58:
            dict_ids_strings[each_string] = each_string[-46:]
        if len(each_string) == 57:
            dict_ids_strings[each_string] = each_string[-45:]
    return dict_ids_strings


def isChanReply(text):
    dict_ids_strings = {}
    list_strings = re.findall(r'(?<!\S)&gt;&gt;&gt;BM-[a-zA-Z0-9]{34}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{33}|&gt;&gt;&gt;BM-[a-zA-Z0-9]{32}', text)
    for each_string in list_strings:
        if len(each_string) == 49:
            dict_ids_strings[each_string] = each_string[-37:]
        if len(each_string) == 48:
            dict_ids_strings[each_string] = each_string[-36:]
        if len(each_string) == 47:
            dict_ids_strings[each_string] = each_string[-35:]
    return dict_ids_strings


def format_body(body):
    """
    Formatting of post body text at time of page render
    Mostly to allow links to properly form after initial message processing from bitmessage
    """
    if not body:
        return ""

    lines = body.split("<br/>")

    regex_passphrase = r"""(\[\"(private|public)\"\,\s\"(board|list)\"\,\s\".{1,25}?\"\,\s\".{1,128}?\"\,\s\[(\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\[(\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\[(\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\[((\"BM\-[a-zA-Z0-9]{32,34}(\"\,\s)?|\"?)*\]\,\s\{(.*?)(\})|(\}\}))\,\s\"(.*?)\"\])"""
    regex_passphrase_base64_link = r"""http\:\/\/(172\.28\.1\.1|\blocalhost\b)\:8000\/join_base64\/([A-Za-z0-9+&]+={0,2})(\s|\Z)"""
    regex_address = r'(\[identity\](BM\-[a-zA-Z0-9]{32,34})\[\/identity\])'

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
                    p=base64.b64encode(passphrase.encode()).decode(), d=pass_info["description"], l=link_text)
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
            passphrase_encoded = each_find.groups()[1]
            passphrase_dict_json = base64.b64decode(
                passphrase_encoded.replace("&", "/")).decode()
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
                    p=passphrase_encoded, d=pass_info["description"], l=link_text)
            if url:
                lines[line] = lines[line].replace(link.strip(), url, 1)

        # Search and replace Post Reply ID with link
        dict_ids_strings = is_post_id_reply(lines[line])
        if dict_ids_strings:
            for each_string, targetpostid in dict_ids_strings.items():
                # Determine if OP or identity/address book label is to be appended to reply post ID
                name_str = ""
                message = Messages.query.filter(
                    Messages.message_id.endswith(targetpostid.lower())).first()
                if message:
                    if message.thread.op_sha256_hash == message.message_sha256_hash:
                        name_str = " (OP)"
                    identity = Identity.query.filter(
                        Identity.address == message.address_from).first()
                    if not name_str and identity and identity.label:
                        name_str = " (You, {})".format(identity.label)
                    address_book = AddressBook.query.filter(
                        AddressBook.address == message.address_from).first()
                    if not name_str and address_book and address_book.label:
                        name_str = " ({})".format(address_book.label)
                # replace body reply with link
                rep_str = "<a class=\"link\" class=\"underlined link\" href=\"#{}\">{}{}</a>".format(
                    targetpostid, each_string, name_str)
                lines[line] = lines[line].replace(each_string, rep_str)

        # Search and replace BM address with post ID with link
        dict_chans_threads_strings = isChanThreadReply(lines[line])
        if dict_chans_threads_strings:
            for each_string, each_address in dict_chans_threads_strings.items():
                address_split = each_address.split("/")
                chan_entry = db_return(Chan).filter(and_(
                    Chan.type == "board",
                    Chan.address == address_split[0])).first()
                if chan_entry:
                    from bitchan_flask import nexus
                    for each_page in range(1, 99):
                        thread = nexus.get_chan_threads(chan_entry.address, each_page)
                        if not thread:
                            break
                        for each_thread in thread:
                            for each_post in each_thread.posts:
                                thread_db = db_return(Threads).filter(
                                    Threads.thread_hash == each_post.thread_id).first()
                                if thread_db and address_split[1] == each_post.post_id:
                                    lines[line] = lines[line].replace(
                                        each_string,
                                        '<a  class="link" href="/thread/{a}/{t}#{p}" title="{d} // {s}">>>>/{l}/{p}</a>'.format(
                                            a=each_post.chan, t=each_post.thread_id,
                                            d=chan_entry.description.replace('"', '&quot;'), s=thread_db.subject.replace('"', '&quot;'),
                                            l=html.escape(chan_entry.label), p=each_post.post_id))
                                    break

        # Search and replace only BM address with link
        dict_chans_strings = isChanReply(lines[line])
        if dict_chans_strings:
            for each_string, each_address in dict_chans_strings.items():
                chan_entry = db_return(Chan).filter(and_(
                    Chan.type == "board",
                    Chan.address == each_address)).first()
                list_entry = db_return(Chan).filter(and_(
                    Chan.type == "list",
                    Chan.address == each_address)).first()
                if chan_entry:
                    lines[line] = lines[line].replace(
                        each_string,
                        '<a class=" link"href="/board/{a}/1" title="{d}">>>>/{l}/</a>'.format(
                            a=each_address, d=chan_entry.description.replace('"', '&quot;'), l=html.escape(chan_entry.label)))
                elif list_entry:
                    lines[line] = lines[line].replace(
                        each_string,
                        '<a class="link" href="/list/{a}" title="{d}">>>>/{l}/</a>'.format(
                            a=each_address, d=list_entry.description, l=list_entry.label))

        list_links = []
        for each_word in lines[line].split(" "):
            parsed = parse.urlparse(each_word)
            if parsed.scheme and parsed.netloc:
                list_links.append(parsed.geturl())
        for each_link in list_links:
            lines[line] = lines[line].replace(
                each_link,
                '<a class="link" href="{l}" target="_blank">{l}</a>'.format(l=each_link))

    return "<br/>".join(lines)


def eliminate_buddy(op_matches, cl_matches):
    """eliminate last match that doesn't have a buddy"""
    if len(op_matches) + len(cl_matches) % 2 != 0:
        if len(op_matches) > len(cl_matches):
            op_matches.pop()
        if len(cl_matches) > len(op_matches):
            cl_matches.pop()
    return op_matches, cl_matches


def replace_two_regex(body, start_regex, end_regex, start_tag, end_tag):
    op_matches = re.findall(start_regex, body)
    cl_matches = re.findall(end_regex, body)
    op_matches, cl_matches = eliminate_buddy(op_matches, cl_matches)

    matches = []
    for i in range(len(op_matches)):
        matches.append(op_matches[i])
        matches.append(cl_matches[i])

    if body and len(matches) > 1:
        for i, pair in enumerate(pairs(matches)):
            body = body.replace(pair[0], start_tag, 1)
            body = body.replace(pair[1], end_tag, 1)

    return body


def replace_ascii(text):
    list_replacements = []
    for each_find in re.finditer(r"(?i)\[aa](.*?)\[\/aa]", text, flags=re.DOTALL):
        list_replacements.append({
            "ID": get_random_alphanumeric_string(
                30, with_punctuation=False, with_spaces=False),
            "string_with_tags": each_find.group(),
            "string_wo_tags": each_find.groups()[0]
        })
    return list_replacements


def replace_ascii_small(text):
    list_replacements = []
    for each_find in re.finditer(r"(?i)\[aa\-s](.*?)\[\/aa\-s]", text, flags=re.DOTALL):
        list_replacements.append({
            "ID": get_random_alphanumeric_string(
                30, with_punctuation=False, with_spaces=False),
            "string_with_tags": each_find.group(),
            "string_wo_tags": each_find.groups()[0]
        })
    return list_replacements


def replace_ascii_xsmall(text):
    list_replacements = []
    for each_find in re.finditer(r"(?i)\[aa\-xs](.*?)\[\/aa\-xs]", text, flags=re.DOTALL):
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
    regex = r'\[\bcandy\b\](.*?)\[\/\bcandy\b\]'
    matches_full = re.finditer(regex, body, flags=re.DOTALL)

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
    op_matches = re.findall(r"((\[color=)(\(#(?:[0-9a-fA-F]{3}){1,2})\)\])", body)
    cl_matches = re.findall(r"\[\/color\]", body)
    color_codes = re.findall(r"#(?:[0-9a-fA-F]{3}){1,2}", body)
    op_matches, cl_matches = eliminate_buddy(op_matches, cl_matches)

    start_tag = []
    for i in color_codes:
        start_tag.append('<span style="color:{};">'.format(i))

    end_tag = "</span>"

    matches = []
    for i in range(len(op_matches)):
        matches.append(op_matches[i][0])
        matches.append(cl_matches[i])

    if body and len(matches) > 1:
        for i, pair in enumerate(pairs(matches)):
            body = body.replace(pair[0], start_tag[i], 1)
            body = body.replace(pair[1], end_tag, 1)

    return body


def replace_pair(body, start_tag, end_tag, pair):
    try:
        matches = [i.start() for i in re.finditer(pair, body)]

        if body and len(matches) > 1:
            list_replace = []
            for pair in pairs(matches):
                # strings with and without the tags
                str_w = body[pair[0]: pair[1] + 2]
                str_wo = body[pair[0] + 2: pair[1]]
                list_replace.append((str_w, str_wo))

            for rep in list_replace:
                body = body.replace(rep[0], "{}{}{}".format(start_tag, rep[1], end_tag), 1)
    except Exception:
        logger.exception("replace pair")
    finally:
        return body


def replace_green_pink_text(text):
    lines = text.split("\n")
    for line in range(len(lines)):
        # Search and replace greentext
        if (len(lines[line]) > 1 and
                ((lines[line].startswith("&gt;") and lines[line][4:8] != "&gt;") or
                 (lines[line].startswith(">") and lines[line][1] != ">"))):
            lines[line] = "<span class=\"greentext\">{}</span>".format(lines[line])

        # Search and replace pinktext
        if (len(lines[line]) > 1 and
                ((lines[line].startswith("&lt;") and lines[line][4:8] != "&lt;") or
                 (lines[line].startswith("<") and lines[line][1] != "<"))):
            lines[line] = "<span style=\"color: #E0727F\">{}</span>".format(lines[line])

    return "\n".join(lines)


def youtube_url_validation(url):
    """Determine if URL is a link to a youtube video and return video ID"""
    youtube_regex = (
        r'(https?://)?(www\.)?'
        '(youtube|youtu|youtube-nocookie)\.(com|be)/'
        '(watch\?.*?(?=v=)v=|embed/|v/|.+\?v=)?([^&=%\?]{11})')

    youtube_regex_match = re.match(youtube_regex, url)
    if youtube_regex_match and youtube_regex_match.group(6):
        return youtube_regex_match.group(6)


def replace_youtube(text):
    regex = r'\[\byoutube\b\](.*?)\[\/\byoutube\b\]'

    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(regex, lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
                if match_index == i:
                    each_find = re.search(regex, lines[line_index])
                    yt_url = each_find.groups()[0]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    if find_count > 2:  # Process max of 2 per message
                        lines[line_index] = '{s}<a class="link" href="{l}" target="_blank">{l}</a>{e}'.format(
                            s=start_string, l=yt_url, e=end_string)
                    else:
                        yt_id = youtube_url_validation(yt_url)
                        middle_string = '<iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/{id}" ' \
                                        'frameborder="0" allow="encrypted-media" allowfullscreen></iframe>'.format(id=yt_id)
                        find_count += 1
                        lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_dict_keys_with_values(body, filter_dict):
    """replace keys with values from input dictionary"""
    for key, value in filter_dict.items():
        body = re.sub(r"\b{}\b".format(key), value, body)
    return body


def process_replacements(body, seed, message_id):
    """Replace portions of text for formatting and text generation purposes"""

    # ASCII processing Stage 1 of 2 (must be before all text style formatting)
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

    # body = replace_youtube(body)  # deprecated
    body = replace_green_pink_text(body)
    body = replace_colors(body)
    body = replace_candy(body)

    # Simple replacements
    body = replacements_simple.replace_8ball(body, seed)
    body = replacements_simple.replace_card_pulls(body, seed)
    body = replacements_simple.replace_countdown(body)
    body = replacements_simple.replace_dice_rolls(body, seed)
    body = replacements_simple.replace_flip_flop(body, seed)
    body = replacements_simple.replace_iching(body, seed)
    body = replacements_simple.replace_rock_paper_scissors(body, seed)
    body = replacements_simple.replace_rune_b_pulls(body, seed)
    body = replacements_simple.replace_rune_pulls(body, seed)
    body = replacements_simple.replace_tarot_c_pulls(body, seed)
    body = replacements_simple.replace_tarot_pulls(body, seed)

    try:  # these have the highest likelihood of unknown failure
        body = replacements_simple.replace_stich(body, seed)
        body = replacements_simple.replace_god_song(body, seed, message_id)
    except:
        logger.exception("stich or god_song exception")

    body = replace_pair(body, "<mark>", "</mark>", "``")
    body = replace_pair(body, """<sup style="font-size: smaller;">""", "</sup>", "\^\^")
    body = replace_pair(body, """<sub style="font-size: smaller;">""", "</sub>", "\%\%")
    body = replace_pair(body, "<strong>", "</strong>", "@@")
    body = replace_pair(body, "<i>", "</i>", "~~")
    body = replace_pair(body, "<u>", "</u>", "__")
    body = replace_pair(body, "<s>", "</s>", "\+\+")
    body = replace_pair(body, '<span class="replace-small">', '</span>', "--")
    body = replace_pair(body, '<span class="replace-big">', '</span>', "##")
    body = replace_pair(body, '<span style="color:#F00000">', '</span>', "\^r")
    body = replace_pair(body, '<span style="color:#57E8ED">', '</span>', "\^b")
    body = replace_pair(body, '<span style="color:#FFA500">', '</span>', "\^o")
    body = replace_pair(body, '<span style="color:#3F99CC">', '</span>', "\^c")
    body = replace_pair(body, '<span style="color:#A248A5">', '</span>', "\^p")
    body = replace_pair(body, '<span style="color:#B67C55">', '</span>', "\^t")
    body = replace_pair(body, '<span class="replace-shadow">', '</span>', "\^s")
    body = replace_pair(body, '<span class="replace-spoiler">', '</span>', "\*\*")

    body = replace_two_regex(
        body,
        r'\[\bmeme\b\]',r'\[\/\bmeme\b\]',
        '<span style="background: linear-gradient(to right, red, orange, yellow, green, blue, indigo, violet); '
        '-webkit-background-clip: text; -webkit-text-fill-color: transparent;">',
        "</span>")
    body = replace_two_regex(
        body,
        r'\[\bautism\b\]', r'\[\/\bautism\b\]',
        '<span class="animated">',
        "</span>")
    body = replace_two_regex(
        body,
        r'\[\bflash\b\]', r'\[\/\bflash\b\]',
        '<span class="replace-blinking">',
        "</span>")
    body = replace_two_regex(
        body,
        r'\[\bcenter\b\]', r'\[\/\bcenter\b\]',
        '<div style="text-align: center;">',
        "</div>")
    body = replace_two_regex(
        body,
        r'\[\bback\b\]', r'\[\/\bback\b\]',
        '<bdo dir="rtl">',
        "</bdo>")
    body = replace_two_regex(
        body,
        r'\[\bcaps\b\]', r'\[\/\bcaps\b\]',
        '<span style="font-variant: small-caps;">',
        "</span>")
    body = replace_two_regex(
        body,
        r'\[\bkern\b\]', r'\[\/\bkern\b\]',
        '<span style="letter-spacing: 5px;">',
        "</span>")

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
            str_final = '<span class="language-ascii-art">{}</span>'.format(
                each_ascii_replace["string_wo_tags"])
            body = body.replace(each_ascii_replace["ID"], str_final, 1)

    if ascii_replacements_small:
        # Replace ID strings with ASCII text and formatted tags
        for each_ascii_replace in ascii_replacements_small:
            str_final = '<span class="language-ascii-art-s">{}</span>'.format(
                each_ascii_replace["string_wo_tags"])
            body = body.replace(each_ascii_replace["ID"], str_final, 1)

    if ascii_replacements_xsmall:
        # Replace ID strings with ASCII text and formatted tags
        for each_ascii_replace in ascii_replacements_xsmall:
            str_final = '<span class="language-ascii-art-xs">{}</span>'.format(
                each_ascii_replace["string_wo_tags"])
            body = body.replace(each_ascii_replace["ID"], str_final, 1)

    return body

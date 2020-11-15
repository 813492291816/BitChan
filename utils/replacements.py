import html
import logging
import random
import re
import time
from urllib.parse import urlparse

import htmllistparse
import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectTimeout
from sqlalchemy import and_
from user_agent import generate_user_agent

from config import DATABASE_BITCHAN
from config import FILE_DIRECTORY
from config import TOR_PROXIES
from database.models import AddressBook
from database.models import Chan
from database.models import Identity
from database.models import Messages
from database.utils import db_return
from utils.files import LF
from utils.general import get_random_alphanumeric_string
from utils.general import is_int
from utils.general import pairs
from utils.god_song_01 import make_god_song_01

DB_PATH = 'sqlite:///' + DATABASE_BITCHAN

logger = logging.getLogger("bitchan.utils.replacements")


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
    for line in range(len(lines)):
        # Search and replace Reply ID with link
        dict_ids_strings = is_post_id_reply(lines[line])
        if dict_ids_strings:
            for each_string, targetpostid in dict_ids_strings.items():
                # Determine if OP or identity/address book label is to be appended to reply post ID
                name_str = ""
                message = Messages.query.filter(
                    Messages.message_id.endswith(targetpostid.lower())).first()
                if message:
                    if message.thread.op_md5_hash == message.message_md5_hash:
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
                rep_str = "<a class=\"underlined link\" href=\"#{}\">{}{}</a>".format(
                    targetpostid, each_string, name_str)
                lines[line] = lines[line].replace(
                    each_string, rep_str)

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
                                if address_split[1] == each_post.post_id:
                                    lines[line] = lines[line].replace(
                                        each_string, '<a href="/thread/{a}/{t}#{p}">>>>{a}/{p}</a>'.format(
                                            a=each_post.chan, t=each_post.thread_id, p=each_post.post_id))
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
                        each_string, '<a href="/board/{l}/1">>>>{l}</a>'.format(l=each_address))
                elif list_entry:
                    lines[line] = lines[line].replace(
                        each_string, '<a href="/list/{l}">>>>{l}</a>'.format(l=each_address))

        list_links = []
        for each_word in lines[line].split(" "):
            parsed = urlparse(each_word)
            if parsed.scheme and parsed.netloc:
                list_links.append(parsed.geturl())
        for each_link in list_links:
            lines[line] = lines[line].replace(each_link, '<a href="{l}" target="_blank">{l}</a>'.format(l=each_link))

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


def replace_candy(body):
    open_tag_1 = '<span style="color: blue;">'
    open_tag_2 = '<span style="color: red;">'
    close_tag = '</span>'

    match = r'\[\bcandy\b\](.*?)\[\/\bcandy\b\]'
    matches_full = re.finditer(match, body, flags=re.DOTALL)
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


def replace_dice_rolls(text, seed):
    lines = text.split("\n")
    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#(\d*)d(\d+)", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#(\d*)d(\d+)", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    number_dice =  each_find.groups()[0]
                    sides_dice = each_find.groups()[1]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]

                    rolls_str = []
                    rolls_int = []
                    dice_rolls = 1
                    if is_int(number_dice):
                        dice_rolls = int(number_dice)

                    if dice_rolls > 100:
                        logger.error("Too many die rolls: {}. Must be equal or less than 100".format(
                            dice_rolls))
                        continue

                    for _ in range(dice_rolls):
                        if is_int(sides_dice):
                            if int(sides_dice) > 1000000000:
                                logger.error("Too many die sides: {}. Must be equal or less than 1,000,000,000.".format(
                                    sides_dice))
                                continue
                            rolls_str.append(str(random.randint(1, int(sides_dice))))

                    for roll_str in rolls_str:
                        rolls_int.append(int(roll_str))

                    if len(rolls_str) > 1:
                        middle_string = '<span class="replace-funcs">{}({} = {})</span>'.format(
                            match, " + ".join(rolls_str), sum(rolls_int))
                    else:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, rolls_str[0])

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_flip_flop(text, seed):
    dict_flip_flap = {
        0: "flip",
        1: "flap"
    }

    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#flip", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#flip", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                        match, dict_flip_flap[random.randint(0, 1)])
                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_card_pulls(text, seed):
    cards = [
        "2♠", "3♠", "4♠", "5♠", "6♠", "7♠", "8♠", "9♠", "10♠", "J♠", "Q♠", "K♠", "A♠",
        "2♥", "3♥", "4♥", "5♥", "6♥", "7♥", "8♥", "9♥", "10♥", "J♥", "Q♥", "K♥", "A♥",
        "2♦", "3♦", "4♦", "5♦", "6♦", "7♦", "8♦", "9♦", "10♦", "J♦", "Q♦", "K♦", "A♦",
        "2♣", "3♣", "4♣", "5♣", "6♣", "7♣", "8♣", "9♣", "10♣", "J♣", "Q♣", "K♣", "A♣",
    ]
    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#c(\d+)", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#c(\d+)", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    number_cards = each_find.groups()[0]

                    cards_str = []
                    cards_index = []
                    if is_int(number_cards) and 0 < int(number_cards) < 53:
                        card_pulls = int(number_cards)
                    else:
                        continue

                    # generate random indexes without repeats
                    while len(cards_index) < card_pulls:
                        rand_int = random.randint(0, 51)
                        if rand_int not in cards_index:
                            cards_index.append(rand_int)

                    # pull cards with indexes
                    for each_index in cards_index:
                        cards_str.append(cards[each_index])

                    if len(cards_str) > 1:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, " ".join(cards_str))
                    else:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, cards_str[0])

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_8ball(text, seed):
    list_8ball = [
        "It is certain",
        "It is decidedly so",
        "Without a doubt",
        "Yes – definitely",
        "You may rely on it",
        "As I see it, yes",
        "Most likely",
        "Outlook good",
        "Yes",
        "Signs point to yes",
        "Reply hazy, try again",
        "Ask again later",
        "Better not tell you now",
        "Cannot predict now",
        "Concentrate and ask again",
        "Don't count on it",
        "My reply is no",
        "My sources say no",
        "Outlook not so good",
        "Very doubtful"
    ]

    lines = text.split("\n")

    find_count = 0
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#8ball", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#8ball", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                        match, random.choice(list_8ball))
                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def get_book_url_from_id(book_id):
    book_directory = None
    book_url_content = None
    mirror_index = 0

    mirrors = [
        "https://aleph.gutenberg.org",
        "https://gutenberg.pglaf.org",
        "https://mirrors.xmission.com/gutenberg",
        "https://mirror.csclub.uwaterloo.ca/gutenberg",
        "https://www.mirrorservice.org/sites/ftp.ibiblio.org/pub/docs/books/gutenberg",
        "http://gutenberg.readingroo.ms",
    ]

    url_append = ""
    for i, each_char in enumerate(str(book_id)):
        if i + 1 == len(str(book_id)):
            break
        url_append += "/{}".format(each_char)
    url_append += "/{}".format(book_id)

    for _ in range(len(mirrors)):
        try:
            book_directory = mirrors[mirror_index] + url_append
            book_url_content = requests.get(
                book_directory,
                proxies=TOR_PROXIES,
                headers={'User-Agent': generate_user_agent()},
                allow_redirects=True,
                timeout=10)
            break
        except ConnectTimeout:
            if mirror_index + 1 < len(mirrors):
                mirror_index += 1
            else:
                mirror_index = 0

    soup = BeautifulSoup(book_url_content.text, "html.parser")
    wd, listing = htmllistparse.parse(soup)

    for each_list in listing:
        if each_list.name == "{}.txt".format(book_id):
            filename = each_list.name
            return "{}/{}".format(book_directory, filename)

    for each_list in listing:
        if each_list.name.startswith(str(book_id)) and each_list.name.endswith(".txt"):
            filename = each_list.name
            return "{}/{}".format(book_directory, filename)


def split_into_sentences(text):
    alphabets = "([A-Za-z])"
    prefixes = "(Mr|St|Mrs|Ms|Dr)[.]"
    suffixes = "(Inc|Ltd|Jr|Sr|Co)"
    romannum = "(I|II|III|IV|V|VI|VII|VIII|IX|X|XI|XII|XIII|XIV|XV|XVI|XVII|XVIII|XIX|XX|XXI|XXII|XXIII|XXIV|XXV)"
    starters = "(Mr|Mrs|Ms|Dr|He\s|She\s|It\s|They\s|Their\s|Our\s|We\s|But\s|However\s|That\s|This\s|Wherever)"
    acronyms = "([A-Z][.][A-Z][.](?:[A-Z][.])?)"
    websites = "[.](com|net|org|io|gov)"

    text = " " + text + "  "
    text = text.replace("\n", " ")
    text = text.replace("e.g.", "e<prd>g<prd>")
    text = text.replace("i.e.", "i<prd>e<prd>")
    text = re.sub(r" (\d+)[.](\d+) ", " \\1<prd>\\2 ", text)  # decimal numbers
    text = re.sub(prefixes, "\\1<prd>", text)
    text = re.sub(romannum + "[.]", "\\1<prd>", text)
    text = re.sub(websites, "<prd>\\1", text)
    if "Ph.D" in text: text = text.replace("Ph.D.", "Ph<prd>D<prd>")
    text = re.sub("\s" + alphabets + "[.] ", " \\1<prd> ", text)
    text = re.sub(acronyms + " " + starters, "\\1<stop> \\2", text)
    text = re.sub(alphabets + "[.]" + alphabets + "[.]" + alphabets + "[.]", "\\1<prd>\\2<prd>\\3<prd>", text)
    text = re.sub(alphabets + "[.]" + alphabets + "[.]","\\1<prd>\\2<prd>", text)
    text = re.sub(" " + suffixes + "[.] " + starters, " \\1<stop> \\2", text)
    text = re.sub(" " + suffixes + "[.]", " \\1<prd>", text)
    text = re.sub(" " + alphabets + "[.]", " \\1<prd>", text)
    if "”" in text: text = text.replace(".”", "”.")
    if "\"" in text: text = text.replace(".\"", "\".")
    if "!" in text: text = text.replace("!\"", "\"!")
    if "?" in text: text = text.replace("?\"", "\"?")
    text = text.replace(".", ".<stop>")
    text = text.replace("?", "?<stop>")
    text = text.replace("!", "!<stop>")
    text = text.replace("<prd>", ".")
    sentences = text.split("<stop>")
    sentences = sentences[:-1]
    sentences = [s.strip() for s in sentences]
    return sentences


def make_quote_from_book(lines_book, random_):
    lines_book = split_into_sentences(lines_book)
    index_book_start = None
    for index, line in enumerate(lines_book):
        if "*** START OF" in line or "***START OF" in line:
            index_book_start = index
            break

    index_book_end = None
    for index, line in enumerate(lines_book):
        if ("End of the Project Gutenberg EBook" in line or
                "*** END OF THIS PROJECT GUTENBERG" in line or
                "***END OF THIS PROJECT GUTENBERG" in line or
                "End of Project Gutenberg's" in line):
            index_book_end = index
            break

    if not index_book_start:
        index_book_start = 50
    if not index_book_end:
        index_book_end = len(lines_book)

    for _ in range(100):
        try:
            line_number = random_.randint(index_book_start + 1, index_book_end - 1)
        except:
            return

        random_line = lines_book[line_number]
        random_line = " ".join(random_line.splitlines())
        random_line = random_line.replace("[\n\r\t\v\f]", " ")
        random_line = random_line.lstrip()
        random_line = re.sub(' +', ' ', random_line)

        if len(random_line) > 6:
            return line_number, random_line


def stichomancy_pull(seed, select_book_id=None):
    random.seed(seed)

    author = None
    title = None
    language = None

    full_book_url = None
    for _ in range(7):
        if select_book_id:
            book_id = select_book_id
        else:
            book_id = random.randrange(0, 60000)

        full_book_url = get_book_url_from_id(book_id)

        try:
            book = requests.get(
                full_book_url,
                proxies=TOR_PROXIES,
                headers={'User-Agent': generate_user_agent()},
                allow_redirects=True)
            lines_book = book.content.decode()
        except:
            return None, None, None, None

        for each_line in lines_book.split("\n"):
            if not author and each_line.strip().startswith("Author: "):
                author = each_line.strip().split(": ", 1)[1]
            if not title and each_line.strip().startswith("Title: "):
                title = each_line.strip().split(": ", 1)[1]
            if not language and each_line.strip().startswith("Language: "):
                language = each_line.strip().split(": ", 1)[1]
            if author and title and language:
                break

        if select_book_id:
            break
        if (language and "English" in language) and author and title:
            break
        time.sleep(3)

    if (not select_book_id and
            ((language and "English" not in language) or
             not language or
             not author or
             not title)):
        return None, None, None, None

    line_number, quote = make_quote_from_book(lines_book, random)
    return (line_number,
            quote.replace("\"", "'").replace("“", "'").replace("”", "'"),
            full_book_url,
            title,
            author)


def replace_stich(text, message_id):
    lines = text.split("\n")
    stichomancy_lf = "/var/lock/stichomancy.lock"
    lf = LF()

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#stich", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#stich", lines[line_index])):
                if find_count > 2:  # Process max of 2 per message
                    return "\n".join(lines)
                elif match_index == i:
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    count = 0
                    try:
                        while True:
                            count += 1
                            new_seed = "{}{}{}{}".format(message_id, line_index, i, match_index)
                            random_quote = None
                            quote = None
                            author = None
                            title = None
                            url = None
                            if lf.lock_acquire(stichomancy_lf, to=600):
                                try:
                                    _, quote, url, title, author = stichomancy_pull(new_seed)
                                finally:
                                    lf.lock_release(stichomancy_lf)
                            if quote:
                                title_str = title
                                if author and "Various" not in author:
                                    title_str += " by {}".format(author)

                                random_quote = "\"{quote}\" -<a href=\"{url}\">{title}</a>".format(
                                    quote=quote, url=url, title=title_str)
                            if random_quote or count > 5:
                                break
                    except:
                        time.sleep(3)
                        continue
                    middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                        match, random_quote)

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_tarot_pulls(text, seed):
    tcards = [
        # 78 CARDS IN A DECK, 156 POSSIBILITIES WHEN UPSIDE DOWN CARDS ARE INCLUDED

        # MAJOR ARCANA
        ("The Fool", "The Fool (↓)"),
        ("The Magician", "The Magician (↓)"),
        ("The High Priestess", "The High Priestess (↓)"),
        ("The Empress", "The Empress (↓)"),
        ("The Emperor", "The Emperor (↓)"),
        ("The Hierophant", "The Hierophant (↓)"),
        ("The Lovers", "The Lovers (↓)"),
        ("The Chariot", "The Chariot (↓)"),
        ("Strength", "Strength (↓)"),
        ("The Hermit", "The Hermit (↓)"),
        ("Wheel of Fortune", "Wheel of Fortune (↓)"),
        ("Justice", "Justice (↓)"),
        ("The Hanged Man", "The Hanged Man (↓)"),
        ("Death", "Death (↓)"),
        ("Temperance", "Temperance (↓)"),
        ("The Devil", "The Devil (↓)"),
        ("The Tower", "The Tower (↓)"),
        ("The Star", "The Star (↓)"),
        ("The Moon", "The Moon (↓)"),
        ("The Sun", "The Sun (↓)"),
        ("Judgement", "Judgement (↓)"),
        ("The World", "The World (↓)"),

        #Wands
        ("Ace of Wands", "Ace of Wands (↓)"),
        ("Two of Wands", "Two of Wands (↓)"),
        ("Three of Wands", "Three of Wands (↓)"),
        ("Four of Wands", "Four of Wands (↓)"),
        ("Five of Wands", "Five of Wands (↓)"),
        ("Six of Wands", "Six of Wands (↓)"),
        ("Seven of Wands", "Seven of Wands (↓)"),
        ("Eight of Wands", "Eight of Wands (↓)"),
        ("Nine of Wands", "Nine of Wands (↓)"),
        ("Ten of Wands", "Ten of Wands (↓)"),
        ("Page of Wands", "Page of Wands (↓)"),
        ("Knight of Wands", "Knight of Wands (↓)"),
        ("Queen of Wands", "Queen of Wands (↓)"),
        ("King of Wands", "King of Wands (↓)"),

        #Cups
        ("Ace of Cups", "Ace of Cups (↓)"),
        ("Two of Cups", "Two of Cups (↓)"),
        ("Three of Cups", "Three of Cups (↓)"),
        ("Four of Cups", "Four of Cups (↓)"),
        ("Five of Cups", "Five of Cups (↓)"),
        ("Six of Cups", "Six of Cups (↓)"),
        ("Seven of Cups", "Seven of Cups (↓)"),
        ("Eight of Cups", "Eight of Cups (↓)"),
        ("Nine of Cups", "Nine of Cups (↓)"),
        ("Ten of Cups", "Ten of Cups (↓)"),
        ("Page of Cups", "Page of Cups (↓)"),
        ("Knight of Cups", "Knight of Cups (↓)"),
        ("Queen of Cups", "Queen of Cups (↓)"),
        ("King of Cups", "King of Cups (↓)"),

        #Swords
        ("Ace of Swords", "Ace of Swords (↓)"),
        ("Two of Swords", "Two of Swords (↓)"),
        ("Three of Swords", "Three of Swords (↓)"),
        ("Four of Swords", "Four of Swords (↓)"),
        ("Five of Swords", "Five of Swords (↓)"),
        ("Six of Swords", "Six of Swords (↓)"),
        ("Seven of Swords", "Seven of Swords (↓)"),
        ("Eight of Swords", "Eight of Swords (↓)"),
        ("Nine of Swords", "Nine of Swords (↓)"),
        ("Ten of Swords", "Ten of Swords (↓)"),
        ("Page of Swords", "Page of Swords (↓)"),
        ("Knight of Swords", "Knight of Swords (↓)"),
        ("Queen of Swords", "Queen of Swords (↓)"),
        ("King of Swords", "King of Swords (↓)"),

        # COINS
        ("Ace of Coins", "Ace of Coins (↓)"),
        ("Two of Coins", "Two of Coins (↓)"),
        ("Three of Coins", "Three of Coins (↓)"),
        ("Four of Coins", "Four of Coins (↓)"),
        ("Five of Coins", "Five of Coins (↓)"),
        ("Six of Coins", "Six of Coins (↓)"),
        ("Seven of Coins", "Seven of Coins (↓)"),
        ("Eight of Coins", "Eight of Coins (↓)"),
        ("Nine of Coins", "Nine of Coins (↓)"),
        ("Ten of Coins", "Ten of Coins (↓)"),
        ("Page of Coins", "Page of Coins (↓)"),
        ("Knight of Coins", "Knight of Coins (↓)"),
        ("Queen of Coins", "Queen of Coins (↓)"),
        ("King of Coins", "King of Coins (↓)")
    ]
    lines = text.split("\n")

    find_count = 1
    for line_index in range(0, len(lines)):
        number_finds = len(re.findall(r"(?i)#t(\d+)", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#t(\d+)", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    number_tcards = each_find.groups()[0]

                    tcards_str = []
                    tcards_index = []
                    if is_int(number_tcards) and 0 < int(number_tcards) < 79:
                        tcard_pulls = int(number_tcards)
                    else:
                        continue

                    # generate random indexes without repeats
                    while len(tcards_index) < tcard_pulls:
                        rand_int = random.randint(0, 77)
                        if rand_int not in tcards_index:
                            tcards_index.append(rand_int)

                    # pull tcards with indexes
                    for each_index in tcards_index:
                        tcards_str.append(tcards[each_index][random.randint(0, 1)])

                    if len(tcards_str) > 1:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, ", ".join(tcards_str))
                    else:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, tcards_str[0])

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_ctarot_pulls(text, seed):
    ctcards = [
        # 78 CARDS IN A DECK, 156 POSSIBILITIES WHEN UPSIDE DOWN CARDS ARE INCLUDED

        # MAJOR ARCANA
        ("The Fool", "The Fool (↓)"),
        ("The Magician", "The Magician (↓)"),
        ("The High Priestess", "The High Priestess (↓)"),
        ("The Empress", "The Empress (↓)"),
        ("The Emperor", "The Emperor (↓)"),
        ("The Hierophant", "The Hierophant (↓)"),
        ("The Lovers", "The Lovers (↓)"),
        ("The Chariot", "The Chariot (↓)"),
        ("Lust", "Lust (↓)"),
        ("The Hermit", "The Hermit (↓)"),
        ("Fortune", "Fortune (↓)"),
        ("Adjustment", "Adjustment (↓)"),
        ("The Hanged Man", "The Hanged Man (↓)"),
        ("Death", "Death (↓)"),
        ("Art", "Art (↓)"),
        ("The Devil", "The Devil (↓)"),
        ("The Tower", "The Tower (↓)"),
        ("The Star", "The Star (↓)"),
        ("The Moon", "The Moon (↓)"),
        ("The Sun", "The Sun (↓)"),
        ("Aeon", "Aeon (↓)"),
        ("The Universe", "The Universe (↓)"),

        # WANDS
        ("Ace of Wands", "Ace of Wands (↓)"),
        ("Two of Wands", "Two of Wands (↓)"),
        ("Three of Wands", "Three of Wands (↓)"),
        ("Four of Wands", "Four of Wands (↓)"),
        ("Five of Wands", "Five of Wands (↓)"),
        ("Six of Wands", "Six of Wands (↓)"),
        ("Seven of Wands", "Seven of Wands (↓)"),
        ("Eight of Wands", "Eight of Wands (↓)"),
        ("Nine of Wands", "Nine of Wands (↓)"),
        ("Ten of Wands", "Ten of Wands (↓)"),
        ("Princess of Wands", "Princess of Wands (↓)"),
        ("Prince of Wands", "Prince of Wands (↓)"),
        ("Queen of Wands", "Queen of Wands (↓)"),
        ("King of Wands", "King of Wands (↓)"),

        # CUPS
        ("Ace of Cups", "Ace of Cups (↓)"),
        ("Two of Cups", "Two of Cups (↓)"),
        ("Three of Cups", "Three of Cups (↓)"),
        ("Four of Cups", "Four of Cups (↓)"),
        ("Five of Cups", "Five of Cups (↓)"),
        ("Six of Cups", "Six of Cups (↓)"),
        ("Seven of Cups", "Seven of Cups (↓)"),
        ("Eight of Cups", "Eight of Cups (↓)"),
        ("Nine of Cups", "Nine of Cups (↓)"),
        ("Ten of Cups", "Ten of Cups (↓)"),
        ("Princess of Cups", "Princess of Cups (↓)"),
        ("Prince of Cups", "Prince of Cups (↓)"),
        ("Queen of Cups", "Queen of Cups (↓)"),
        ("King of Cups", "King of Cups (↓)"),

        # SWORDS
        ("Ace of Swords", "Ace of Swords (↓)"),
        ("Two of Swords", "Two of Swords (↓)"),
        ("Three of Swords", "Three of Swords (↓)"),
        ("Four of Swords", "Four of Swords (↓)"),
        ("Five of Swords", "Five of Swords (↓)"),
        ("Six of Swords", "Six of Swords (↓)"),
        ("Seven of Swords", "Seven of Swords (↓)"),
        ("Eight of Swords", "Eight of Swords (↓)"),
        ("Nine of Swords", "Nine of Swords (↓)"),
        ("Ten of Swords", "Ten of Swords (↓)"),
        ("Princess of Swords", "Princess of Swords (↓)"),
        ("Prince of Swords", "Prince of Swords (↓)"),
        ("Queen of Swords", "Queen of Swords (↓)"),
        ("King of Swords", "King of Swords (↓)"),

        # COINS
        ("Ace of Coins", "Ace of Coins (↓)"),
        ("Two of Coins", "Two of Coins (↓)"),
        ("Three of Coins", "Three of Coins (↓)"),
        ("Four of Coins", "Four of Coins (↓)"),
        ("Five of Coins", "Five of Coins (↓)"),
        ("Six of Coins", "Six of Coins (↓)"),
        ("Seven of Coins", "Seven of Coins (↓)"),
        ("Eight of Coins", "Eight of Coins (↓)"),
        ("Nine of Coins", "Nine of Coins (↓)"),
        ("Ten of Coins", "Ten of Coins (↓)"),
        ("Princess of Coins", "Princess of Coins (↓)"),
        ("Prince of Coins", "Prince of Coins (↓)"),
        ("Queen of Coins", "Queen of Coins (↓)"),
        ("King of Coins", "King of Coins (↓)")
    ]
    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#ct(\d+)", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#ct(\d+)", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    number_ctcards = each_find.groups()[0]

                    ctcards_str = []
                    ctcards_index = []
                    if is_int(number_ctcards) and 0 < int(number_ctcards) < 79:
                        tcard_pulls = int(number_ctcards)
                    else:
                        continue

                    # generate random indexes without repeats
                    while len(ctcards_index) < tcard_pulls:
                        rand_int = random.randint(0, 77)
                        if rand_int not in ctcards_index:
                            ctcards_index.append(rand_int)

                    # pull ctcards with indexes
                    for each_index in ctcards_index:
                        ctcards_str.append(ctcards[each_index][random.randint(0, 1)])

                    if len(ctcards_str) > 1:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, ", ".join(ctcards_str))
                    else:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, ctcards_str[0])

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_iching(text, seed):
    name = {
        1: """1. <span style="font-family: iching;">䷀</span> CH'IEN / THE CREATIVE""",
        2: """2. <span style="font-family: iching;">䷁</span> K'UN / THE RECEPTIVE, EARTH""",
        3: """3. <span style="font-family: iching;">䷂</span> CHUN / DIFFICULTY AT THE BEGINNING""",
        4: """4. <span style="font-family: iching;">䷃</span> MÊNG / YOUTHFUL FOLLY""",
        5: """5. <span style="font-family: iching;">䷄</span> HSÜ / WAITING (NOURISHMENT)""",
        6: """6. <span style="font-family: iching;">䷅</span> SUNG / CONFLICT""",
        7: """7. <span style="font-family: iching;">䷆</span> SHIH / THE ARMY""",
        8: """8. <span style="font-family: iching;">䷇</span> PI / HOLDING TOGETHER (UNION)""",
        9: """9. <span style="font-family: iching;">䷈</span> HSIAO CH'U / THE TAMING POWER OF THE SMALL""",
        10: """10. <span style="font-family: iching;">䷉</span> LÜ / TREADING (CONDUCT)""",
        11: """11. <span style="font-family: iching;">䷊</span> T'AI / PEACE""",
        12: """12. <span style="font-family: iching;">䷋</span> P'I / STANDSTILL (STAGNATION)""",
        13: """13. <span style="font-family: iching;">䷌</span> T'UNG JÊN / FELLOWSHIP WITH MEN""",
        14: """14. <span style="font-family: iching;">䷍</span> TA YU / POSSESSION IN GREAT MEASURE""",
        15: """15. <span style="font-family: iching;">䷎</span> CH'IEN / MODESTY""",
        16: """16. <span style="font-family: iching;">䷏</span> YÜ / ENTHUSIASM""",
        17: """17. <span style="font-family: iching;">䷐</span> SUI / FOLLOWING""",
        18: """18. <span style="font-family: iching;">䷑</span> KU / WORK ON WHAT HAS BEEN SPOILED (DECAY)""",
        19: """19. <span style="font-family: iching;">䷒</span> LIN / APPROACH""",
        20: """20. <span style="font-family: iching;">䷓</span> KUAN / CONTEMPLATION (VIEW)""",
        21: """21. <span style="font-family: iching;">䷔</span> SHIH HO / BITING THROUGH""",
        22: """22. <span style="font-family: iching;">䷕</span> PI / GRACE""",
        23: """23. <span style="font-family: iching;">䷖</span> PO / SPLITTING APART""",
        24: """24. <span style="font-family: iching;">䷗</span> FU / RETURN (THE TURNING POINT)""",
        25: """25. <span style="font-family: iching;">䷘</span> WU WANG / INNOCENCE (THE UNEXPECTED)""",
        26: """26. <span style="font-family: iching;">䷙</span> TA CH'U / THE TAMING POWER OF THE GREAT""",
        27: """27. <span style="font-family: iching;">䷚</span> I / CORNERS OF THE MOUTH (PROVIDING NOURISHMENT)""",
        28: """28. <span style="font-family: iching;">䷛</span> TA KUO / PREPONDERANCE OF THE GREAT""",
        29: """29. <span style="font-family: iching;">䷜</span> K'AN / THE ABYSMAL (WATER)""",
        30: """30. <span style="font-family: iching;">䷝</span> LI / THE CLINGING, FIRE""",
        31: """31. <span style="font-family: iching;">䷞</span> HSIEN / INFLUENCE (WOOING)""",
        32: """32. <span style="font-family: iching;">䷟</span> HÊNG / DURATION""",
        33: """33. <span style="font-family: iching;">䷠</span> TUN / RETREAT""",
        34: """34. <span style="font-family: iching;">䷡</span> TA CHUANG / THE POWER OF THE GREAT""",
        35: """35. <span style="font-family: iching;">䷢</span> CHIN / PROGRESS""",
        36: """36. <span style="font-family: iching;">䷣</span> MING I / DARKENING OF THE LIGHT""",
        37: """37. <span style="font-family: iching;">䷤</span> CHIA JÊN / THE FAMILY (THE CLAN)""",
        38: """38. <span style="font-family: iching;">䷥</span> K'UEI / OPPOSITION""",
        39: """39. <span style="font-family: iching;">䷦</span> CHIEN / OBSTRUCTION""",
        40: """40. <span style="font-family: iching;">䷧</span> HSIEH / DELIVERANCE""",
        41: """41. <span style="font-family: iching;">䷨</span> SUN / DECREASE""",
        42: """42. <span style="font-family: iching;">䷩</span> I / INCREASE""",
        43: """43. <span style="font-family: iching;">䷪</span> KUAI / BREAK-THROUGH (RESOLUTENESS)""",
        44: """44. <span style="font-family: iching;">䷫</span> KOU / COMING TO MEET""",
        45: """45. <span style="font-family: iching;">䷬</span> TS'UI / GATHERING TOGETHER (MASSING)""",
        46: """46. <span style="font-family: iching;">䷭</span> SHÊNG / PUSHING UPWARD""",
        47: """47. <span style="font-family: iching;">䷮</span> K'UN / OPPRESSION (EXHAUSTION)""",
        48: """48. <span style="font-family: iching;">䷯</span> CHING / THE WELL""",
        49: """49. <span style="font-family: iching;">䷰</span> KO / REVOLUTION (MOLTING)""",
        50: """50. <span style="font-family: iching;">䷱</span> TING / THE CALDRON""",
        51: """51. <span style="font-family: iching;">䷲</span> CHÊN / THE AROUSING (SHOCK, THUNDER)""",
        52: """52. <span style="font-family: iching;">䷳</span> KÊN / KEEPING STILL, MOUNTAIN""",
        53: """53. <span style="font-family: iching;">䷴</span> CHIEN / DEVELOPMENT (GRADUAL PROGRESS)""",
        54: """54. <span style="font-family: iching;">䷵</span> KUEI MEI / THE MARRYING MAIDEN""",
        55: """55. <span style="font-family: iching;">䷶</span> FÊNG / ABUNDANCE (FULLNESS)""",
        56: """56. <span style="font-family: iching;">䷷</span> LÜ / THE WANDERER""",
        57: """57. <span style="font-family: iching;">䷸</span> SUN / THE GENTLE (THE PENETRATING, WIND)""",
        58: """58. <span style="font-family: iching;">䷹</span> TUI / THE JOYOUS, LAKE""",
        59: """59. <span style="font-family: iching;">䷺</span> HUAN / DISPERSION (DISSOLUTION)""",
        60: """60. <span style="font-family: iching;">䷻</span> CHIEH / LIMITATION""",
        61: """61. <span style="font-family: iching;">䷼</span> CHUNG FU / INNER TRUTH""",
        62: """62. <span style="font-family: iching;">䷽</span> HSIAO KUO / PREPONDERANCE OF THE SMALL""",
        63: """63. <span style="font-family: iching;">䷾</span> CHI CHI / AFTER COMPLETION""",
        64: """64. <span style="font-family: iching;">䷿</span> WEI CHI / BEFORE COMPLETION"""
    }

    yin_yang = [  # ratio 3/8+3/8+1/8+1/8
        '-   -', '-   -', '-   -', '-----', '-----', '-----', '- x -', '--o--'
    ]

    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#iching", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#iching", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]

                    def return_binary(hexagram):
                        bline1 = 0 if hexagram[0] in ['-   -', '- x -'] else 1
                        bline2 = 0 if hexagram[1] in ['-   -', '- x -'] else 1
                        bline3 = 0 if hexagram[2] in ['-   -', '- x -'] else 1
                        bline4 = 0 if hexagram[3] in ['-   -', '- x -'] else 1
                        bline5 = 0 if hexagram[4] in ['-   -', '- x -'] else 1
                        bline6 = 0 if hexagram[5] in ['-   -', '- x -'] else 1
                        hexagram = [bline6, bline5, bline4, bline3, bline2, bline1]
                        return int("".join(str(x) for x in hexagram), 2)

                    def mutate(hexagram):
                        mline1 = '-   -' if hexagram[0] in ['--o--', '-   -'] else '-----'
                        mline2 = '-   -' if hexagram[1] in ['--o--', '-   -'] else '-----'
                        mline3 = '-   -' if hexagram[2] in ['--o--', '-   -'] else '-----'
                        mline4 = '-   -' if hexagram[3] in ['--o--', '-   -'] else '-----'
                        mline5 = '-   -' if hexagram[4] in ['--o--', '-   -'] else '-----'
                        mline6 = '-   -' if hexagram[5] in ['--o--', '-   -'] else '-----'
                        mutation = [mline6, mline5, mline4, mline3, mline2, mline1]
                        return mutation

                    def convert_and_mutate(hexagram):
                        hexagram_1 = return_binary(hexagram)
                        hexagram_2 = return_binary(mutate(hexagram))
                        return hexagram_1, hexagram_2

                    hexagram = []

                    for _ in range(6):
                        hexagram.append(random.choice(yin_yang))

                    hexagrams = convert_and_mutate(hexagram)

                    if hexagrams[0] == hexagrams[1]:
                        str_return = "{}".format(name[hexagrams[0] + 1])
                    else:
                        str_return = """{} <span style="font-family: arrow;">🢂</span> {}""".format(
                            name[hexagrams[0] + 1], name[hexagrams[1] + 1])

                    middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                        match, str_return)

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_brune_pulls(text, seed):
    runes = [
        # ELDER FUTHARK RUNE ALPHABET WITH BLANK
        ("""<span style="font-family: runes;">ᚠ</span> - FEHU (WEALTH)""", """<span style="font-family: runes;">ᚠ</span> - FEHU Rev. (LOSS)"""),
        ("""<span style="font-family: runes;">ᚢ</span> - URUZ (STRENGTH)""", """<span style="font-family: runes;">ᚢ</span> - URUZ Rev. (WEAKNESS)"""),
        ("""<span style="font-family: runes;">ᚦ</span> - THURISAZ (PROTECTION)""", """<span style="font-family: runes;">ᚦ</span> - THURISAZ Rev. (STUBBORN)"""),
        ("""<span style="font-family: runes;">ᚨ</span> - ANSUZ (WISDOM)""", """<span style="font-family: runes;">ᚨ</span> - ANSUZ Rev. (TRICKERY)"""),
        ("""<span style="font-family: runes;">ᚱ</span> - RAIDO (JOURNEY)""", """<span style="font-family: runes;">ᚱ</span> - RAIDO Rev. (CRISIS OR STANDSTILL)"""),
        ("""<span style="font-family: runes;">ᚲ</span> - KAUNA (TORCH)""", """<span style="font-family: runes;">ᚲ</span> - KAUNA Rev. (WITHDRAWAL)"""),
        ("""<span style="font-family: runes;">ᚷ</span> - GEBO (MARRIAGE)""", """<span style="font-family: runes;">ᚷ</span> - GEBO (MARRIAGE)"""),
        ("""<span style="font-family: runes;">ᚹ</span> - WUNJO (JOY)""", """<span style="font-family: runes;">ᚹ</span> - WUNJO Rev. (SORROW)"""),
        ("""<span style="font-family: runes;">ᚺ</span> - HAGLAZ (DISRUPTION)""", """<span style="font-family: runes;">ᚺ</span> - HAGLAZ (DISRUPTION)"""),
        ("""<span style="font-family: runes;">ᚾ</span> - NAUDIZ (CONSTRAINT)""", """<span style="font-family: runes;">ᚾ</span> - NAUDIZ Rev. (IMPROPER COURSE OF ACTION)"""),
        ("""<span style="font-family: runes;">ᛁ</span> - ISA (STANDSTILL)""", """<span style="font-family: runes;">ᛁ</span> - ISA (STANDSTILL)"""),
        ("""<span style="font-family: runes;">ᛃ</span> - JERA (SUCCESS)""", """<span style="font-family: runes;">ᛃ</span> - JERA (SUCCESS)"""),
        ("""<span style="font-family: runes;">ᛇ</span> - IWAZ (SAFTEY)""", """<span style="font-family: runes;">ᛇ</span> - IWAZ (SAFTEY)"""),
        ("""<span style="font-family: runes;">ᛈ</span> - PERTHO (CHANCE AND BECOMING)""", """<span style="font-family: runes;">ᛈ</span> - PERTHO Rev. (EVENTS STALLED)"""),
        ("""<span style="font-family: runes;">ᛉ</span> - ALGIZ (FRIENDSHIP)""", """<span style="font-family: runes;">ᛉ</span> - ALGIZ Rev. (VULNERABILITY)"""),
        ("""<span style="font-family: runes;">ᛋ</span> - SOWILO (SELF)""", """<span style="font-family: runes;">ᛋ</span> - SOWILO (SELF)"""),
        ("""<span style="font-family: runes;">ᛏ</span> - TIWAZ (VICTORY)""", """<span style="font-family: runes;">ᛏ</span> - TIWAZ Rev. (LOW ENERGY, COWARDICE)"""),
        ("""<span style="font-family: runes;">ᛒ</span> - BERKANAN (LOVE)""", """<span style="font-family: runes;">ᛒ</span> - BERKANAN Rev. (UNFORTUNATE DOMESTIC SITUATION)"""),
        ("""<span style="font-family: runes;">ᛖ</span> - EHWAZ (TRUST)""", """<span style="font-family: runes;">ᛖ</span> - EHWAZ Rev. (SUDDEN UNWANTED CHANGE)"""),
        ("""<span style="font-family: runes;">ᛗ</span> - MANNAZ (HUMANITY)""", """<span style="font-family: runes;">ᛗ</span> - MANNAZ (ENEMY)"""),
        ("""<span style="font-family: runes;">ᛚ</span> - LAGUZ (HEALING)""", """<span style="font-family: runes;">ᛚ</span> - LAGUZ Rev. (BLOCKED HELP)"""),
        ("""<span style="font-family: runes;">ᛝ</span> - INGUZ (FERTILITY)""", """<span style="font-family: runes;">ᛝ</span> - INGUZ (FERTILITY)"""),
        ("""<span style="font-family: runes;">ᛟ</span> - OTHILA (STABLE PROSPERITY)""", """<span style="font-family: runes;">ᛟ</span> - OTHILA Rev. (DISOWNMENT, STUCK IN OLD IDEAS)"""),
        ("""<span style="font-family: runes;">ᛞ</span> - DAGAZ (HOME)""", """<span style="font-family: runes;">ᛞ</span> - DAGAZ (HOME)"""),
        ("""<span style="font-family: runes;">□</span> - BLANK (DESTINY)""", """<span style="font-family: runes;">□</span> - BLANK (DESTINY)""")
    ]
    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#rb(\d+)", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#rb(\d+)", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    number_runes = each_find.groups()[0]

                    runes_str = []
                    runes_index = []
                    if is_int(number_runes) and 0 < int(number_runes) < 26:
                        rune_pulls = int(number_runes)
                    else:
                        continue

                    # generate random indexes without repeats
                    while len(runes_index) < rune_pulls:
                        rand_int = random.randint(0, 24)
                        if rand_int not in runes_index:
                            runes_index.append(rand_int)

                    # pull runes with indexes
                    for each_index in runes_index:
                        runes_str.append(runes[each_index][random.randint(0, 1)])

                    if len(runes_str) > 1:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, ", ".join(runes_str))
                    else:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, runes_str[0])

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_rune_pulls(text, seed):
    runes = [
        # ELDER FUTHARK RUNE ALPHABET WITHOUT BLANK
        ("""<span style="font-family: runes;">ᚠ</span> - FEHU (WEALTH)""", """<span style="font-family: runes;">ᚠ</span> - FEHU Rev. (LOSS)"""),
        ("""<span style="font-family: runes;">ᚢ</span> - URUZ (STRENGTH)""", """<span style="font-family: runes;">ᚢ</span> - URUZ Rev. (WEAKNESS)"""),
        ("""<span style="font-family: runes;">ᚦ</span> - THURISAZ (PROTECTION)""", """<span style="font-family: runes;">ᚦ</span> - THURISAZ Rev. (STUBBORN)"""),
        ("""<span style="font-family: runes;">ᚨ</span> - ANSUZ (WISDOM)""", """<span style="font-family: runes;">ᚨ</span> - ANSUZ Rev. (TRICKERY)"""),
        ("""<span style="font-family: runes;">ᚱ</span> - RAIDO (JOURNEY)""", """<span style="font-family: runes;">ᚱ</span> - RAIDO Rev. (CRISIS OR STANDSTILL)""",),
        ("""<span style="font-family: runes;">ᚲ</span> - KAUNA (TORCH)""", """<span style="font-family: runes;">ᚲ</span> - KAUNA Rev. (WITHDRAWAL)"""),
        ("""<span style="font-family: runes;">ᚷ</span> - GEBO (MARRIAGE)""", """<span style="font-family: runes;">ᚷ</span> - GEBO (MARRIAGE)"""),
        ("""<span style="font-family: runes;">ᚹ</span> - WUNJO (JOY)""", """<span style="font-family: runes;">ᚹ</span> - WUNJO Rev. (SORROW)"""),
        ("""<span style="font-family: runes;">ᚺ</span> - HAGLAZ (DISRUPTION)""", """<span style="font-family: runes;">ᚺ</span> - HAGLAZ (DISRUPTION)"""),
        ("""<span style="font-family: runes;">ᚾ</span> - NAUDIZ (CONSTRAINT)""", """<span style="font-family: runes;">ᚾ</span> - NAUDIZ Rev. (IMPROPER COURSE OF ACTION)"""),
        ("""<span style="font-family: runes;">ᛁ</span> - ISA (STANDSTILL)""", """<span style="font-family: runes;">ᛁ</span> - ISA (STANDSTILL)"""),
        ("""<span style="font-family: runes;">ᛃ</span> - JERA (SUCCESS)""", """<span style="font-family: runes;">ᛃ</span> - JERA (SUCCESS)"""),
        ("""<span style="font-family: runes;">ᛇ</span> - IWAZ (SAFTEY)""", """<span style="font-family: runes;">ᛇ</span> - IWAZ (SAFTEY)"""),
        ("""<span style="font-family: runes;">ᛈ</span> - PERTHO (CHANCE AND BECOMING)""", """<span style="font-family: runes;">ᛈ</span> - PERTHO Rev. (EVENTS STALLED)"""),
        ("""<span style="font-family: runes;">ᛉ</span> - ALGIZ (FRIENDSHIP)""", """<span style="font-family: runes;">ᛉ</span> - ALGIZ Rev. (VULNERABILITY)"""),
        ("""<span style="font-family: runes;">ᛋ</span> - SOWILO (SELF)""", """<span style="font-family: runes;">ᛋ</span> - SOWILO (SELF)"""),
        ("""<span style="font-family: runes;">ᛏ</span> - TIWAZ (VICTORY)""", """<span style="font-family: runes;">ᛏ</span> - TIWAZ Rev. (LOW ENERGY, COWARDICE)"""),
        ("""<span style="font-family: runes;">ᛒ</span> - BERKANAN (LOVE)""", """<span style="font-family: runes;">ᛒ</span> - BERKANAN Rev. (UNFORTUNATE DOMESTIC SITUATION)"""),
        ("""<span style="font-family: runes;">ᛖ</span> - EHWAZ (TRUST)""", """<span style="font-family: runes;">ᛖ</span> - EHWAZ Rev. (SUDDEN UNWANTED CHANGE)"""),
        ("""<span style="font-family: runes;">ᛗ</span> - MANNAZ (HUMANITY)""", """<span style="font-family: runes;">ᛗ</span> - MANNAZ (ENEMY)"""),
        ("""<span style="font-family: runes;">ᛚ</span> - LAGUZ (HEALING)""", """<span style="font-family: runes;">ᛚ</span> - LAGUZ Rev. (BLOCKED HELP)"""),
        ("""<span style="font-family: runes;">ᛝ</span> - INGUZ (FERTILITY)""", """<span style="font-family: runes;">ᛝ</span> - INGUZ (FERTILITY)"""),
        ("""<span style="font-family: runes;">ᛟ</span> - OTHILA (STABLE PROSPERITY)""", """<span style="font-family: runes;">ᛟ</span> - OTHILA Rev. (DISOWNMENT, STUCK IN OLD IDEAS)"""),
        ("""<span style="font-family: runes;">ᛞ</span> - DAGAZ (HOME)""", """<span style="font-family: runes;">ᛞ</span> - DAGAZ (HOME)""")
    ]
    lines = text.split("\n")

    find_count = 1
    for line_index in range(len(lines)):
        number_finds = len(re.findall(r"(?i)#r(\d+)", lines[line_index]))
        for i in range(number_finds):
            for match_index, each_find in enumerate(re.finditer(r"(?i)#r(\d+)", lines[line_index])):
                if find_count > 25:  # Process max of 25 per message
                    return "\n".join(lines)
                elif match_index == i:
                    random.seed(seed + str(line_index) + str(match_index))
                    match = lines[line_index][each_find.start():each_find.end()]
                    start_string = lines[line_index][:each_find.start()]
                    end_string = lines[line_index][each_find.end():]
                    number_runes = each_find.groups()[0]

                    runes_str = []
                    runes_index = []
                    if is_int(number_runes) and 0 < int(number_runes) < 25:
                        rune_pulls = int(number_runes)
                    else:
                        continue

                    # generate random indexes without repeats
                    while len(runes_index) < rune_pulls:
                        rand_int = random.randint(0, 23)
                        if rand_int not in runes_index:
                            runes_index.append(rand_int)

                    # pull runes with indexes
                    for each_index in runes_index:
                        runes_str.append(runes[each_index][random.randint(0, 1)])

                    if len(runes_str) > 1:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, ", ".join(runes_str))
                    else:
                        middle_string = '<span class="replace-funcs">{}({})</span>'.format(
                            match, runes_str[0])

                    find_count += 1
                    lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


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

bible_books ={
    185: "The First Book of Moses: Called Genesis",
    5389: "The Second Book of Moses: Called Exodus",
    9709: "The Third Book of Moses: Called Leviticus",
    12882: "The Fourth Book of Moses: Called Numbers",
    17402: "The Fifth Book of Moses: Called Deuteronomy",
    21005: "The Book of Joshua",
    23473: "The Book of Judges",
    25855: "The Book of Ruth",
    26190: "The First Book of Samuel, otherwise called the First Book of the Kings",
    29324: "The Second Book of Samuel, otherwise called the Second Book of the Kings",
    31945: "The First Book of the Kings, commonly called the Third Book of the Kings",
    35035: "The Second Book of the Kings, commonly called the Fourth Book of the Kings",
    37881: "The First Book of the Chronicles",
    40947: "The Second Book of the Chronicles",
    44237: "Ezra",
    45259: "The Book of Nehemiah",
    46710: "The Book of Esther",
    47413: "The Book of Job",
    50585: "The Book of Psalms",
    57931: "The Proverbs",
    60639: "Ecclesiastes, or, The Preacher",
    61417: "The Song of Solomon",
    61814: "The Book of the Prophet Isaiah",
    66637: "The Book of the Prophet Jeremiah",
    71963: "The Lamentations of Jeremiah",
    72469: "The Book of the Prophet Ezekiel",
    77372: "The Book of Daniel",
    78828: "Hosea",
    79540: "Joel",
    79816: "Amos",
    80380: "Obadiah",
    80473: "Jonah",
    80655: "Micah",
    81064: "Nahum",
    81256: "Habakkuk",
    81473: "Zephaniah",
    81689: "Haggai",
    81843: "Zechariah",
    82662: "Malachi",
    82895: "The Gospel According to Saint Matthew",
    86353: "The Gospel According to Saint Mark",
    88536: "The Gospel According to Saint Luke",
    92289: "The Gospel According to Saint John",
    95062: "The Acts of the Apostles",
    98497: "The Epistle of Paul the Apostle to the Romans",
    99909: "The First Epistle of Paul the Apostle to the Corinthians",
    101300: "The Second Epistle of Paul the Apostle to the Corinthians",
    102173: "The Epistle of Paul the Apostle to the Galatianss",
    102655: "The Epistle of Paul the Apostle to the Ephesians",
    103145: "The Epistle of Paul the Apostle to the Philippians",
    103479: "The Epistle of Paul the Apostle to the Colossians",
    103795: "The First Epistle of Paul the Apostle to the Thessalonians",
    104090: "The Second Epistle of Paul the Apostle to the Thessalonians",
    104257: "The First Epistle of Paul the Apostle to Timothy",
    104629: "The Second Epistle of Paul the Apostle to Timothy",
    104905: "The Epistle of Paul the Apostle to Titus",
    105065: "The Epistle of Paul the Apostle to Philemon",
    105147: "The Epistle of Paul the Apostle to the Hebrews",
    106169: "The General Epistle of James",
    106526: "The First Epistle General of Peter",
    106892: "The Second General Epistle of Peter",
    107130: "The First Epistle General of John",
    107492: "The Second Epistle General of John",
    107544: "The Third Epistle General of John",
    107599: "The General Epistle of Jude",
    107700: "The Revelation of Saint John the Devine"
}

def replace_god_song(text, seed, message_id):
    lines = text.split("\n")
    stichomancy_lf = "/var/lock/stichomancy.lock"
    lf = LF()

    first_match = True
    find_count = 1
    for line_index in range(len(lines)):
        for i, each_find in enumerate(re.finditer(r"(?i)#godsong", lines[line_index])):
            if find_count > 10:  # Process max of 10 per message
                return "\n".join(lines)

            match = lines[line_index][each_find.start():each_find.end()]
            start_string = lines[line_index][:each_find.start()]
            end_string = lines[line_index][each_find.end():]
            quote = None
            book_link = None
            if lf.lock_acquire(stichomancy_lf, to=600):
                try:
                    line_number, quote, book_url, title, author = stichomancy_pull(
                        "{}{}{}".format(seed, line_index, i), select_book_id=10900)
                    
                    if not line_number:
                        continue

                    previous_line = 0

                    for i in bible_books:
                        if i > line_number:
                            break
                        previous_line = i

                    title_str = title
                    if author and "Various" not in author:
                        title_str += " by {}".format(title, author)

                    book_link = '<a target="_blank" href="{url}">{name}, {title}</a>'.format(
                        url=book_url, name=bible_books[previous_line], title=title_str)
                finally:
                    lf.lock_release(stichomancy_lf)

            if first_match:  # Only make one God song
                first_match = False
                file_path = "{}/{}_god_song.mp3".format(FILE_DIRECTORY, message_id)
                make_god_song_01(seed=seed, save_path=file_path)
                audio_rep = '<audio class="volume-75" style="width: 325px" controls>' \
                            '<source src="/files/god_song/{}/god_song.mp3" type="audio/mp3">' \
                            '</audio>'.format(message_id)
                if quote:
                    middle_string = '<span class="replace-funcs">{}(</span>{} ' \
                                    '<span class="replace-funcs">{} -{})</span>'.format(
                                        match, audio_rep, quote, book_link)
                else:
                    middle_string = '<span class="replace-funcs">{}</span> {}'.format(
                        match, book_link, audio_rep)
            else:  # After God song, only get random Bible quote
                if quote:
                    middle_string = '<span class="replace-funcs">{}({} -{})</span>'.format(
                        match, quote, book_link)
                else:
                    middle_string = '<span class="replace-funcs">{}</span>'.format(match)

            find_count += 1
            lines[line_index] = start_string + middle_string + end_string

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
            each_find = re.search(regex, lines[line_index])
            yt_url = each_find.groups()[0]
            start_string = lines[line_index][:each_find.start()]
            end_string = lines[line_index][each_find.end():]
            if find_count > 2:  # Process max of 2 per message
                lines[line_index] = '{s}<a href="{l}" target="_blank">{l}</a>{e}'.format(
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
            body = body.replace(each_ascii_replace["string_with_tags"], each_ascii_replace["ID"], 1)

    body = replace_youtube(body)
    body = replace_green_pink_text(body)
    body = replace_colors(body)
    body = replace_candy(body)
    body = replace_dice_rolls(body, seed)
    body = replace_card_pulls(body, seed)
    body = replace_flip_flop(body, seed)
    body = replace_8ball(body, seed)
    body = replace_tarot_pulls(body, seed)
    body = replace_ctarot_pulls(body, seed)
    body = replace_iching(body, seed)
    body = replace_brune_pulls(body, seed)
    body = replace_rune_pulls(body, seed)
    body = replace_pair(body, "<strong>", "</strong>", "@@")
    body = replace_pair(body, "<i>", "</i>", "~~")
    body = replace_pair(body, "<u>", "</u>", "__")
    body = replace_pair(body, "<s>", "</s>", "\+\+")
    body = replace_pair(
        body, '<span class="replace-small">', '</span>', "--")
    body = replace_pair(
        body,
        '<span class="replace-big">',
        '</span>', "==")
    body = replace_pair(body, '<span style="color:#F00000">', '</span>', "\^r")
    body = replace_pair(body, '<span style="color:#57E8ED">', '</span>', "\^b")
    body = replace_pair(body, '<span style="color:#FFA500">', '</span>', "\^o")
    body = replace_pair(body, '<span style="color:#3F99CC">', '</span>', "\^c")
    body = replace_pair(body, '<span style="color:#A248A5">', '</span>', "\^p")
    body = replace_pair(body, '<span style="color:#B67C55">', '</span>', "\^t")
    # shadow text
    body = replace_pair(body, '<span class="replace-shadow">', '</span>', "\^s")
    # spoiler text
    body = replace_pair(body, '<span class="replace-spoiler">', '</span>', "\*\*")
    # meme
    body = replace_two_regex(
        body,
        r'\[\bmeme\b\]',
        r'\[\/\bmeme\b\]',
        '<span style="background: linear-gradient(to right, red, orange, yellow, green, blue, indigo, violet); '
        '-webkit-background-clip: text; -webkit-text-fill-color: transparent;">',
        "</span>")
    # animated meme
    body = replace_two_regex(
        body,
        r'\[\bautism\b\]',
        r'\[\/\bautism\b\]',
        '<span class="animated">',
        "</span>")
    # flashing
    body = replace_two_regex(
        body,
        r'\[\bflash\b\]',
        r'\[\/\bflash\b\]',
        '<span class="replace-blinking">',
        "</span>")
    body = replace_stich(body, seed)
    body = replace_god_song(body, seed, message_id)

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

    return body

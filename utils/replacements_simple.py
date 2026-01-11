import logging
import random
import re
import time

import htmllistparse
import requests
from bs4 import BeautifulSoup
from requests.exceptions import ConnectTimeout
from requests.exceptions import ConnectionError
from user_agent import generate_user_agent

import config
from config import FILE_DIRECTORY
from config import TOR_PROXIES
from database.models import GlobalSettings
from database.utils import session_scope
from utils import replacements_data
from utils.files import LF
from utils.general import get_random_alphanumeric_string
from utils.general import is_int
from utils.god_song_01 import make_god_song_01

logger = logging.getLogger("bitchan.replacements_simple")


class IterFinds:
    """Iterates each line and find number"""
    def __init__(self, lines, regex):
        self.lines = lines
        self.regex = regex
        self.line = None
        self.find = None
        self.dict_lines = {}

        for line_index in range(len(self.lines)):
            self.dict_lines[line_index] = len(re.findall(
                self.regex, self.lines[line_index]))

    def __iter__(self):
        return self

    def __next__(self):
        for each_line, number_finds in self.dict_lines.items():
            if self.line is None:
                self.line = each_line
            if self.line == each_line:
                if not number_finds:
                    self.line += 1
                for each_find in range(number_finds):
                    if self.find is None:
                        self.find = each_find
                        if self.find == number_finds - 1:
                            self.line += 1
                            self.find = None
                        return each_line, each_find
                    elif self.find == number_finds - 1:
                        self.line += 1
                        self.find = None
                        return each_line, each_find
                    else:
                        self.find += 1

        raise StopIteration


def get_book_url_from_id(book_id):
    book_directory = None
    book_url_content = None
    mirror_index = 0

    mirrors = [
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
            logger.info("Trying book URL: {}".format(book_directory))
            book_url_content = requests.get(
                book_directory,
                proxies=TOR_PROXIES,
                headers={'User-Agent': generate_user_agent()},
                allow_redirects=True,
                timeout=10)
            break
        except (ConnectTimeout, ConnectionError) as err:
            logger.error("Mirror {} error: {}".format(book_directory, err))
            if mirror_index + 1 < len(mirrors):
                mirror_index += 1
                logger.info("Trying next mirror")
            else:
                logger.info("Returning to first mirror")
                mirror_index = 0

    if not book_url_content:
        logger.error("Could not connect to any mirrors")
        return

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


def replace_8ball(body, seed):
    matches = re.findall(r"(?i)(?<!\S)#8ball(?!\S)", body)
    random.seed(seed)

    for i in range(1, len(matches) + 1):
        if i > 50:  # Process max of 50 per message
            break
        body = re.sub(
            r"(?i)(?<!\S)#8ball(?!\S)",
            '<span class="replace-funcs">#8ball({choice})</span>'.format(choice=random.choice(
                replacements_data.list_8ball)),
            body, count=1)

    return body


def replace_card_pulls(text, seed):
    cards = [
        "2♠", "3♠", "4♠", "5♠", "6♠", "7♠", "8♠", "9♠", "10♠", "J♠", "Q♠", "K♠", "A♠",
        "2♥", "3♥", "4♥", "5♥", "6♥", "7♥", "8♥", "9♥", "10♥", "J♥", "Q♥", "K♥", "A♥",
        "2♦", "3♦", "4♦", "5♦", "6♦", "7♦", "8♦", "9♦", "10♦", "J♦", "Q♦", "K♦", "A♦",
        "2♣", "3♣", "4♣", "5♣", "6♣", "7♣", "8♣", "9♣", "10♣", "J♣", "Q♣", "K♣", "A♣",
    ]
    regex = r"(?i)(?<!\S)#c(\d+)(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, " ".join(cards_str))
                else:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, cards_str[0])

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_countdown(text):
    regex = r"(?i)(?<!\S)#countdown\((\d*)\)(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 3:  # Process max of 3 per message
                return "\n".join(lines)
            elif match_index == i:
                try:
                    match_epoch = int(each_find.groups()[0])
                except:
                    continue
                start_string = lines[line_index][:each_find.start()]
                end_string = lines[line_index][each_find.end():]
                rand_str = get_random_alphanumeric_string(
                    12, with_punctuation=False, with_spaces=False)

                middle_string = """<span class="replace-funcs">#countdown(</span><span class="replace-funcs countdown_{rand_str}"></span><span class="replace-funcs">)</span><script type="text/javascript">
var countDownDate_{rand_str} = {epoch_end} * 1000;
var x_{rand_str} = setInterval(function() {{
    var now = new Date().getTime();
    var distance = countDownDate_{rand_str} - now;

    var days = Math.floor(distance / (1000 * 60 * 60 * 24));
    var hours = Math.floor((distance % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));
    var minutes = Math.floor((distance % (1000 * 60 * 60)) / (1000 * 60));
    var seconds = Math.floor((distance % (1000 * 60)) / 1000);

    var str_return = "";
    if (days) {{
        str_return += days;
        if (days > 1)  str_return += " Days, ";
        else str_return += " Day, ";
    }};
    if (hours || days) {{
        str_return += hours;
        if (hours > 1) str_return += " Hours, ";
        else str_return += " Hour, ";
    }};
    if (minutes || hours || days) str_return += minutes + " Min, ";
    if (seconds || minutes || hours || days) str_return += seconds + " Sec";

    if (distance < 0) {{
        clearInterval(x_{rand_str});
        var countdowns = document.getElementsByClassName("countdown_{rand_str}");
        for (var i=0; i<countdowns.length; i++) {{
            countdowns[i].innerHTML = "Expired";
        }}
    }} else {{
        var countdowns = document.getElementsByClassName("countdown_{rand_str}");
        for (var i=0; i<countdowns.length; i++) {{
            countdowns[i].innerHTML = str_return;
        }}
    }};
}}, 1000);
</script>""".format(rand_str=rand_str, epoch_end=match_epoch).replace("\n", " ")
                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_dice_rolls(text, seed):
    lines = text.split("\n")
    regex = r"(?i)(?<!\S)#(\d*)d(\d+)(?!\S)"
    find_count = 1

    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                            logger.error(
                                "Too many die sides: {}. "
                                "Must be equal or less than 1,000,000,000.".format(
                                    sides_dice))
                            continue
                        rolls_str.append(str(random.randint(1, int(sides_dice))))

                for roll_str in rolls_str:
                    rolls_int.append(int(roll_str))

                if len(rolls_str) > 1:
                    middle_string = ' <span class="replace-funcs">{}({} = {})</span>'.format(
                        match, " + ".join(rolls_str), sum(rolls_int))
                else:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, rolls_str[0])

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_flip_flop(text, seed):
    dict_flip_flap = {
        0: "flip",
        1: "flap"
    }
    regex = r"(?i)(?<!\S)#flip(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
                return "\n".join(lines)
            elif match_index == i:
                random.seed(seed + str(line_index) + str(match_index))
                match = lines[line_index][each_find.start():each_find.end()]
                start_string = lines[line_index][:each_find.start()]
                end_string = lines[line_index][each_find.end():]
                middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                    match, dict_flip_flap[random.randint(0, 1)])
                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_god_song(text, seed, message_id, preview=False):
    regex = r"(?i)(?<!\S)#godsong(?!\S)"
    lines = text.split("\n")
    stichomancy_lf = "/var/lock/stichomancy.lock"
    lf = LF()

    first_match = True
    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 10:  # Process max of 10 per message
                return "\n".join(lines)
            elif match_index == i:
                match = lines[line_index][each_find.start():each_find.end()]
                start_string = lines[line_index][:each_find.start()]
                end_string = lines[line_index][each_find.end():]
                quote = None
                book_link = None
                if lf.lock_acquire(stichomancy_lf, to=600):
                    try:
                        if preview:
                            line_number = 47414
                            quote = "Fake quote."
                            book_url = "https://fakeurl"
                            title = "Fake Title"
                            author = "Fake Author"
                        else:
                            line_number, quote, book_url, title, author = stichomancy_pull(
                                "{}{}{}".format(seed, line_index, i), select_book_id=10900)

                        if not line_number:
                            continue

                        previous_line = 0

                        for i in replacements_data.bible_books:
                            if i > line_number:
                                break
                            previous_line = i

                        title_str = title
                        if author and "Various" not in author:
                            title_str += f" by {author}"

                        if preview:
                            book_link = f'<a class="link" target="_blank" href="{book_url}">Fake Book, {title_str}</a>'
                        else:
                            book_link = f'<a class="link" target="_blank" href="{book_url}">{replacements_data.bible_books[previous_line]}, {title_str}</a>'
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
                        middle_string = ' <span class="replace-funcs">{}(</span>{} ' \
                                        '<span class="replace-funcs">{} -{})</span>'.format(
                                            match, audio_rep, quote, book_link)
                    else:
                        middle_string = ' <span class="replace-funcs">{}</span> {}'.format(
                            match, book_link, audio_rep)
                else:  # After God song, only get random Bible quote
                    if quote:
                        middle_string = ' <span class="replace-funcs">{}({} -{})</span>'.format(
                            match, quote, book_link)
                    else:
                        middle_string = ' <span class="replace-funcs">{}</span>'.format(match)

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_iching(text, seed):
    yin_yang = [  # ratio 3/8+3/8+1/8+1/8
        '-   -', '-   -', '-   -', '-----', '-----', '-----', '- x -', '--o--'
    ]
    regex = r"(?i)(?<!\S)#iching(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                    str_return = "{}".format(replacements_data.iching[hexagrams[0] + 1])
                else:
                    str_return = """{} <span style="font-family: arrow;">🢂</span> {}""".format(
                        replacements_data.iching[hexagrams[0] + 1],
                        replacements_data.iching[hexagrams[1] + 1])

                middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                    match, str_return)

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_rock_paper_scissors(text, seed):
    dict_rps = {
        0: "rock",
        1: "paper",
        2: "scissors"
    }
    regex = r"(?i)(?<!\S)#rps(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
                return "\n".join(lines)
            elif match_index == i:
                random.seed(seed + str(line_index) + str(match_index))
                match = lines[line_index][each_find.start():each_find.end()]
                start_string = lines[line_index][:each_find.start()]
                end_string = lines[line_index][each_find.end():]
                middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                    match, dict_rps[random.randint(0, 2)])
                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_rune_b_pulls(text, seed):
    regex = r"(?i)(?<!\S)#rb(\d+)(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                    runes_str.append(
                        replacements_data.runes_b[each_index][random.randint(0, 1)])

                if len(runes_str) > 1:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, ", ".join(runes_str))
                else:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, runes_str[0])

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_rune_pulls(text, seed):
    regex = r"(?i)(?<!\S)#r(\d+)(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                    runes_str.append(
                        replacements_data.runes[each_index][random.randint(0, 1)])

                if len(runes_str) > 1:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, ", ".join(runes_str))
                else:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, runes_str[0])

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_stich(text, message_id, preview=False):
    lines = text.split("\n")
    regex = r"(?i)(?<!\S)#stich(?!\S)"
    stichomancy_lf = "/var/lock/stichomancy.lock"
    lf = LF()

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
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
                                if preview:
                                    quote = "Fake quote."
                                    url = "https://fakeurl"
                                    title = "Fake Title"
                                    author = "Fake Author"
                                else:
                                    _, quote, url, title, author = stichomancy_pull(new_seed)
                            except:
                                logger.exception("getting quote")
                            finally:
                                lf.lock_release(stichomancy_lf)
                        if quote:
                            title_str = title
                            if author and "Various" not in author:
                                title_str += " by {}".format(author)

                            random_quote = "\"{quote}\" -<a class=\"link\" href=\"{url}\">{title}</a>".format(
                                quote=quote, url=url, title=title_str)
                        if random_quote or count > 5:
                            break
                except:
                    time.sleep(3)
                    continue
                middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                    match, random_quote)

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_tarot_pulls(text, seed):
    regex = r"(?i)(?<!\S)#t(\d+)(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                    tcards_str.append(
                        replacements_data.tarot[each_index][random.randint(0, 1)])

                if len(tcards_str) > 1:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, ", ".join(tcards_str))
                else:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, tcards_str[0])

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def replace_tarot_c_pulls(text, seed):

    regex = r"(?i)(?<!\S)#ct(\d+)(?!\S)"
    lines = text.split("\n")

    find_count = 1
    lines_finds = IterFinds(lines, regex)
    for line_index, i in lines_finds:
        for match_index, each_find in enumerate(re.finditer(regex, lines[line_index])):
            if find_count > 50:  # Process max of 50 per message
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
                    ctcards_str.append(
                        replacements_data.tarot_c[each_index][random.randint(0, 1)])

                if len(ctcards_str) > 1:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, ", ".join(ctcards_str))
                else:
                    middle_string = ' <span class="replace-funcs">{}({})</span>'.format(
                        match, ctcards_str[0])

                find_count += 1
                lines[line_index] = start_string + middle_string + end_string

    return "\n".join(lines)


def split_into_sentences(text):
    alphabets = "([A-Za-z])"
    prefixes = "(Mr|St|Mrs|Ms|Dr)[.]"
    suffixes = "(Inc|Ltd|Jr|Sr|Co)"
    romannum = "(I|II|III|IV|V|VI|VII|VIII|IX|X|XI|XII|XIII|" \
               "XIV|XV|XVI|XVII|XVIII|XIX|XX|XXI|XXII|XXIII|XXIV|XXV)"
    starters = r"(Mr|Mrs|Ms|Dr|He\s|She\s|It\s|They\s|Their\s|Our\s|" \
               r"We\s|But\s|However\s|That\s|This\s|Wherever)"
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
    text = re.sub(r"\s" + alphabets + "[.] ", " \\1<prd> ", text)
    text = re.sub(acronyms + " " + starters, "\\1<stop> \\2", text)
    text = re.sub(alphabets + "[.]" + alphabets + "[.]" + alphabets + "[.]",
                  "\\1<prd>\\2<prd>\\3<prd>", text)
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


def stichomancy_pull(seed, select_book_id=None):
    with session_scope(config.DB_PATH) as new_session:
        settings = new_session.query(GlobalSettings).first()
        if not settings.allow_net_book_quote:
            # Don't allow connecting to get random quote if setting is False
            return None, None, None, None, None

    author = None
    title = None
    language = None
    lines_book = None

    random.seed(seed)

    full_book_url = None
    for _ in range(7):
        author = None
        title = None
        language = None

        logger.info("Getting book URL")
        if select_book_id:
            book_id = select_book_id
        else:
            book_id = random.randrange(0, 60000)

        full_book_url = get_book_url_from_id(book_id)

        logger.info("Got book URL: {}".format(full_book_url))
        if not full_book_url:
            return None, None, None, None, None

        try:
            book = requests.get(
                full_book_url,
                proxies=TOR_PROXIES,
                headers={'User-Agent': generate_user_agent()},
                allow_redirects=True)
            lines_book = book.content.decode('utf-8', 'ignore')
        except:
            logger.exception("getting book contents")
            return None, None, None, None, None

        for each_line in lines_book.split("\n"):
            if not author and each_line.strip().startswith("Author: "):
                author = each_line.strip().split(": ", 1)[1]
            if not title and each_line.strip().startswith("Title: "):
                title = each_line.strip().split(": ", 1)[1]
            if not language and each_line.strip().startswith("Language: "):
                language = each_line.strip().split(": ", 1)[1]
            if author and title and language:
                logger.info("author and title and language")
                break

        logger.info("Info: {}, {}, {}".format(language, title, author))

        if select_book_id:
            logger.info("select_book_id")
            break
        if (language and "English" in language) and author and title:
            logger.info("English and author and title")
            break
        logger.info("Repeat loop")
        time.sleep(3)

    if (not select_book_id and
            ((language and "English" not in language) or
             not language or
             not author or
             not title or
             not lines_book)):
        logger.error("missing required content: {}, {}, {}, {}, {}".format(
            select_book_id, language, author, title, len(lines_book)))
        return None, None, None, None, None

    line_number, quote = make_quote_from_book(lines_book, random)
    return (line_number,
            quote.replace("\"", "'").replace("“", "'").replace("”", "'"),
            full_book_url,
            title,
            author)

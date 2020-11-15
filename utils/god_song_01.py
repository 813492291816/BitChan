import logging
import os
import random
import sys

from pathlib import Path
from pydub import AudioSegment
from pydub.generators import Sine
from pydub.playback import play

# For executing python file
sys.path.append(os.path.abspath(os.path.join(Path(__file__).parent.absolute(), '..')))

from utils.audio import dur_dict_num
from utils.audio import pitch_dict_note_num
from utils.audio import scale_dict
from utils.audio import vol_dict_num

logger = logging.getLogger('bitchan.utils_audio')

list_beats = [8, 16, 24, 32]

bpm = 100
durations = [bpm * 1.5, bpm * 2, bpm * 3, bpm * 6]

fade_in = [50, 75, 100]
fade_out = [50, 75, 100]


def random_with_complexity(random_, scale, complexity, amount):
    rest_last = True
    rand_list = []

    msg_scale = "Scale: {}".format(scale)
    logger.info(msg_scale)
    print(msg_scale)
    msg_complexity = "Complexity: {}".format(complexity)
    logger.info(msg_complexity)
    print(msg_complexity)
    msg_amount = "Amount: {}".format(amount)
    logger.info(msg_amount)
    print(msg_amount)

    # choose a random start note in that scale
    note_index = random_.randint(0, len(scale_dict[scale]) - 1)

    for _ in range(amount):
        # determine if the next item should be a note or rest
        if not rest_last and random_.randint(0, 100) <= 20:  # Add weight to random rest
            rest_last = True  # DOn't allow two rests in a row
            frequency = 0  # rest
        else:
            # Randomly choose to move up or down scale
            rest_last = False
            mod = random_.randint(-complexity, complexity)
            if note_index + mod < 0:
                note_index = abs(note_index + mod)
            elif note_index + mod > len(scale_dict[scale]) - 1:
                note_index = (note_index + mod) - (len(scale_dict[scale]) - 1)
            else:
                note_index = note_index + mod
            frequency = pitch_dict_note_num[scale_dict[scale][note_index]]

        if complexity == 4:
            first = 30
            second = 19
            third = 14
            fourth = 8
            fifth = 6
            sixth = 4
        elif complexity == 3:
            first = 40
            second = 28
            third = 16
            fourth = 10
            fifth = 7
            sixth = 4
        elif complexity == 2:
            first = 50
            second = 35
            third = 20
            fourth = 12
            fifth = 8
            sixth = 5
        else:
            first = 60
            second = 40
            third = 20
            fourth = 10
            fifth = 5
            sixth = 2

        # determine duration with weight
        dur_index = random_.choices(
            list(dur_dict_num),
            weights=(
                sixth,  # dot_whole
                third,  # whole
                sixth,  # dot_half
                second,  # half
                sixth,  # dot_quarter
                sixth,  # trip_half
                first,  # quart
                fifth,  # dot_eighth
                fifth,  # trip_quarter
                fourth,  # eighth
                sixth,  # dot_sixteenth
                sixth,  # trip_eighth
                fifth,  # sixteenth
                sixth,  # dot_thirty
                sixth,  # thirty
                sixth  # trip_thirty
            ),
            k=1)

        # determine velocity with weight
        vel_index = random_.choices(
            list(vol_dict_num),
            weights=(1, 3, 5, 7, 10, 30, 40, 10),
            k=1)

        rand_list.append({
            "frequency": frequency,
            "duration": dur_dict_num[dur_index[0]],
            "fade_in": random_.choice(fade_in),
            "fade_out": random_.choice(fade_out),
            "velocity": vol_dict_num[vel_index[0]]
        })
    return rand_list


def make_god_song_01(complexity=None, amount=None, seed=None, save_path=None, scale=None):
    logger.info("Generating God song")
    if seed:
        random.seed(seed)
    if not complexity:
        complexity = random.randint(1, 4)
    if not scale:
        scale = random.choice(list(scale_dict))  # choose a random scale
    if not amount:
        amount = random.choice(list_beats)
    result = AudioSegment.silent(duration=0)
    random_list = random_with_complexity(random, scale, complexity, amount)
    # print(random_list)

    for beat in random_list:
        gen = Sine(beat["frequency"])
        sine = gen.to_audio_segment(
            duration=beat["duration"]).apply_gain(beat["velocity"])
        sine = sine.fade_in(beat["fade_in"]).fade_out(beat["fade_out"])
        result += sine

    if save_path:
        result.export(save_path, format="mp3")

    return result


if __name__ == "__main__":
    import datetime
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_path = "/tmp/{} - god song.mp3".format(ts)
    god_song = make_god_song_01(save_path=file_path)
    play(god_song)

    # play(play_scale("phrythian"))

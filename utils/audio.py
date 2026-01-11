import logging

from pydub import AudioSegment
from pydub.generators import Sine

logger = logging.getLogger('bitchan.audio')

list_beats = [8, 16, 24, 32]

# beats per minute (how many quarter notes in a minute assuming 4/4)
bpm = 200
# 1 beat in ms (length in ms of a single quarter note in 4/4)
one_beat = 60000 / bpm
# length of a measure in ms
measure = one_beat * 4


pitch_dict = {
    "A": 440.00,
    "A#": 466.16,
    "B": 493.88,
    "C": 523.25,
    "C#": 554.37,
    "D": 587.33,
    "D#": 622.25,
    "E": 659.25,
    "F": 698.46,
    "F#": 739.99,
    "G": 783.99,
    "G#": 830.61,
    "REST": 0
}

pitch_dict_note_num = {
    0: pitch_dict["A"],
    1: pitch_dict["A#"],
    2: pitch_dict["B"],
    3: pitch_dict["C"],
    4: pitch_dict["C#"],
    5: pitch_dict["D"],
    6: pitch_dict["D#"],
    7: pitch_dict["E"],
    8: pitch_dict["F"],
    9: pitch_dict["F#"],
    10: pitch_dict["G"],
    11: pitch_dict["G#"],
    12: pitch_dict["REST"],
    13: pitch_dict["REST"],
    14: pitch_dict["REST"]
}

scale_dict = {  # complete list of 7 note scales
    "major": [0, 2, 4, 5, 7, 9, 11],
    "dorian": [0, 2, 3, 5, 7, 9, 10],
    "phrygian": [0, 1, 3, 5, 7, 8, 10],
    "lydian": [0, 2, 4, 6, 7, 9, 11],
    "mixolydian": [0, 2, 4, 5, 7, 9, 10],
    "natural_minor": [0, 2, 3, 5, 7, 8, 10],
    "locrian": [0, 1, 3, 5, 6, 8, 10],
    "harmonic_minor": [0, 2, 3, 5, 7, 8, 11],
    "neopolitan_minor": [0, 1, 3, 5, 7, 8, 11],
    "maqam_hüzzam_cedid": [0, 1, 3, 4, 7, 8, 10],
    "maqam_hüzzam_hijaz": [0, 1, 3, 4, 7, 8, 11],
    "sabach": [0, 2, 3, 4, 7, 8, 10],
    "basketmaker_seven": [0, 2, 3, 4, 7, 9, 11],
    "maqam_tarznauyn": [0, 1, 3, 5, 6, 9, 10],
    "maqam_karcigar": [0, 2, 3, 5, 6, 9, 10],
    "maqam_athark_urd": [0, 1, 3, 6, 7, 8, 11],
    "maqam_nawa_athar": [0, 2, 3, 6, 7, 8, 11],
    "blues_7-tone": [0, 3, 5, 6, 7, 10, 11],
    "melodic_minor_ascending": [0, 2, 3, 5, 7, 9, 11],
    "spanish_gypsy": [0, 1, 4, 5, 7, 8, 10],
    "byzantine": [0, 1, 4, 5, 7, 8, 11],
    "arabian": [0, 2, 4, 5, 6, 8, 10],
    "diminished_whole_tone": [0, 1, 3, 4, 6, 8, 10],
    "enigmatic": [0, 1, 4, 6, 8, 10, 11],
    "half_diminished": [0, 2, 3, 5, 6, 8, 10],
    "hindu": [0, 2, 4, 5, 7, 8, 10],
    "hungarian_major": [0, 3, 4, 6, 7, 9, 10],
    "javaneese": [0, 1, 3, 5, 7, 9, 10],
    "leading_whole_tone": [0, 2, 4, 6, 8, 10, 11],
    "lydian_augmented": [0, 2, 4, 6, 8, 9, 11],
    "lydian_minor": [0, 2, 4, 6, 7, 8, 10],
    "lydian_diminished": [0, 2, 3, 6, 7, 9, 11],
    "neapolitan_major": [0, 1, 3, 5, 7, 9, 11],
    "oriental_a": [0, 1, 4, 5, 6, 8, 10],
    "oriental_b": [0, 1, 4, 5, 6, 9, 10],
    "persian": [0, 1, 4, 5, 6, 8, 11],
    "purvi_theta": [0, 1, 4, 6, 7, 8, 11],
    "roumanian_minor": [0, 2, 3, 6, 7, 9, 10],
    "marva": [0, 1, 4, 6, 7, 9, 11],
    "chromatic_mixolydian": [0, 1, 2, 5, 6, 7, 10],
    "chromatic_lydian": [0, 1, 4, 5, 6, 9, 11],
    "chromatic_phrygian": [0, 3, 4, 5, 8, 10, 11],
    "chromatic_hypodorian": [0, 2, 3, 4, 7, 8, 9],
    "chromatic_mixolydian_inverse": [0, 2, 5, 6, 7, 10, 11],
    "chromatic_phrygian_inverse": [0, 1, 2, 4, 7, 8, 9],
    "chromatic_hypophrygian_inverse": [0, 1, 2, 5, 6, 7, 9],
    "chromatic_hypodorian_inverse": [0, 3, 4, 5, 8, 9, 10],
    "ionian_sharp_5": [0, 2, 4, 5, 8, 9, 11],
    "locrian_2": [0, 2, 3, 5, 6, 8, 11],
    "ultra_locrian": [0, 1, 3, 4, 6, 8, 9],
    "locrian_double-flat_7": [0, 1, 3, 5, 6, 8, 9],
    "nohkan_flute": [0, 2, 5, 6, 8, 9, 11],
    "blues_heptatonic_ii": [0, 3, 5, 6, 7, 9, 10],
    "jeths'_mode": [0, 2, 3, 5, 6, 9, 11],
    "modified_blues": [0, 2, 3, 5, 6, 7, 10],
    "enigmatic_descending": [0, 1, 4, 5, 8, 10, 11],
    "hungarian_major_inverse": [0, 2, 3, 5, 6, 8, 9],
    "minor_gypsy_inverse": [0, 2, 4, 5, 6, 9, 10],
    "raga_rageshri": [0, 2, 4, 5, 9, 10, 11],
    "raga_sorati": [0, 2, 5, 7, 9, 10, 11],
    "aeolian_flat_1": [0, 3, 4, 6, 8, 9, 11],
    "raga_madhuri": [0, 4, 5, 7, 9, 10, 11],
    "leading_whole-tone_inverse": [0, 1, 2, 4, 6, 8, 10],
    "debussy's_heptatonic": [0, 2, 3, 4, 5, 6, 9],
    "ultraphrygian": [0, 1, 3, 4, 7, 8, 9],
    "ionian_augmented_#2": [0, 3, 4, 5, 8, 9, 11],
    "locrian_bb3_bb7": [0, 1, 2, 5, 6, 8, 9],
    "kanakangi": [0, 1, 2, 5, 7, 8, 9],
    "ratnangi": [0, 1, 2, 5, 7, 8, 10],
    "ganamoorti": [0, 1, 2, 5, 7, 8, 11],
    "vanaspati": [0, 1, 2, 5, 7, 9, 10],
    "manavati": [0, 1, 2, 5, 7, 9, 11],
    "tanaroopi": [0, 1, 2, 5, 7, 10, 11],
    "senavati": [0, 1, 3, 5, 7, 8, 9],
    "roopavati": [0, 1, 3, 5, 7, 10, 11],
    "gayakapriya": [0, 1, 4, 5, 7, 8, 9],
    "chakravakam": [0, 1, 4, 5, 7, 9, 10],
    "sooryakantam": [0, 1, 4, 5, 7, 9, 11],
    "hatakambari": [0, 1, 4, 5, 7, 10, 11],
    "jhankaradhwani": [0, 2, 3, 5, 7, 8, 9],
    "varunapriya": [0, 2, 3, 5, 7, 10, 11],
    "mararanjani": [0, 2, 4, 5, 7, 8, 9],
    "sarasangi": [0, 2, 4, 5, 7, 8, 11],
    "naganandini": [0, 2, 4, 5, 7, 10, 11],
    "yagapriya": [0, 3, 4, 5, 7, 8, 9],
    "ragavardini": [0, 3, 4, 5, 7, 8, 10],
    "gangeyabhooshani": [0, 3, 4, 5, 7, 8, 11],
    "vagadheeshwari": [0, 3, 4, 5, 7, 9, 10],
    "shoolini": [0, 3, 4, 5, 7, 9, 11],
    "chalanata": [0, 3, 4, 5, 7, 10, 11],
    "salagam": [0, 1, 2, 6, 7, 8, 9],
    "jalarnavam": [0, 1, 2, 6, 7, 8, 10],
    "jhalavarali": [0, 1, 2, 6, 7, 8, 11],
    "navaneetam": [0, 1, 2, 6, 7, 9, 10],
    "pavani": [0, 1, 2, 6, 7, 9, 11],
    "raghupriya": [0, 1, 2, 6, 7, 10, 11],
    "gavambhodi": [0, 1, 3, 6, 7, 8, 9],
    "bhavapriya": [0, 1, 3, 6, 7, 8, 10],
    "shadvidamargini": [0, 1, 3, 6, 7, 9, 10],
    "suvarnangi": [0, 1, 3, 6, 7, 9, 11],
    "divyamani": [0, 1, 3, 6, 7, 10, 11],
    "dhavalambari": [0, 1, 4, 6, 7, 8, 9],
    "namanarayani": [0, 1, 4, 6, 7, 8, 10],
    "ramapriya": [0, 1, 4, 6, 7, 9, 10],
    "vishwambari": [0, 1, 4, 6, 7, 10, 11],
    "shamalangi": [0, 2, 3, 6, 7, 8, 9],
    "shanmukhapriya": [0, 2, 3, 6, 7, 8, 10],
    "neetimati": [0, 2, 3, 6, 7, 10, 11],
    "kantamani": [0, 2, 4, 6, 7, 8, 9],
    "latangi": [0, 2, 4, 6, 7, 8, 11],
    "vachaspati": [0, 2, 4, 6, 7, 9, 10],
    "chitrambari": [0, 2, 4, 6, 7, 10, 11],
    "sucharitra": [0, 3, 4, 6, 7, 8, 9],
    "jyotiswaroopini": [0, 3, 4, 6, 7, 8, 10],
    "dhatuvardani": [0, 3, 4, 6, 7, 8, 11],
    "kosalam": [0, 3, 4, 6, 7, 9, 11],
    "rasikapriya": [0, 3, 4, 6, 7, 10, 11],
    "banshikicho": [0, 2, 3, 4, 7, 9, 10],
    "blues_heptatonic": [0, 3, 4, 5, 6, 7, 10],
    "hijaz_major": [0, 1, 5, 6, 8, 9, 10],
    "raga_bhankar": [0, 1, 4, 5, 6, 8, 9],
    "synthetic_mixture_#5": [0, 2, 4, 6, 8, 9, 10],
    "verdi's_enigmatic_descending": [0, 1, 2, 4, 7, 8, 11],
    "sarian": [0, 1, 2, 4, 5, 7, 9],
    "zoptian": [0, 1, 3, 4, 6, 8, 11],
    "byptian": [0, 1, 3, 5, 8, 9, 10],
    "darian": [0, 2, 4, 7, 8, 9, 11],
    "lonian": [0, 2, 5, 6, 7, 9, 10],
    "phradian": [0, 1, 2, 4, 6, 7, 9],
    "aeolorian": [0, 1, 3, 5, 6, 8, 11],
    "dalian": [0, 2, 3, 5, 8, 9, 10],
    "zolian": [0, 2, 5, 6, 7, 9, 11],
    "stathian": [0, 3, 5, 6, 7, 8, 10],
    "mixonyphian": [0, 2, 3, 4, 5, 7, 9],
    "magian": [0, 1, 2, 3, 5, 7, 10],
    "dadian": [0, 1, 2, 4, 6, 9, 11],
    "aeolylian": [0, 1, 3, 5, 8, 10, 11],
    "gycrian": [0, 2, 4, 7, 9, 10, 11],
    "pyrian": [0, 2, 5, 7, 8, 9, 10],
    "thonian": [0, 3, 5, 6, 8, 10, 11],
    "stadian": [0, 1, 3, 5, 6, 7, 10],
    "thodian": [0, 2, 4, 5, 6, 9, 11],
    "soptian": [0, 3, 5, 7, 8, 9, 10],
    "ionyptian": [0, 2, 4, 5, 6, 7, 9],
    "gyrian": [0, 2, 3, 4, 5, 7, 10],
    "zalian": [0, 1, 2, 3, 5, 8, 10],
    "stolian": [0, 1, 2, 4, 7, 9, 11],
    "bylian": [0, 1, 3, 6, 8, 10, 11],
    "phrolian": [0, 3, 5, 7, 8, 10, 11],
    "kycrian": [0, 1, 3, 4, 5, 8, 10],
    "kagian": [0, 1, 4, 6, 8, 9, 11],
    "zogian": [0, 4, 5, 6, 7, 9, 11],
    "epyrian": [0, 1, 2, 3, 5, 7, 8],
    "lycrian": [0, 1, 2, 4, 6, 7, 11],
    "daptian": [0, 1, 3, 5, 6, 10, 11],
    "mocrian": [0, 2, 3, 7, 8, 9, 10],
    "zynian": [0, 1, 5, 6, 7, 8, 10],
    "aeolacrian": [0, 4, 5, 6, 7, 10, 11],
    "zythian": [0, 1, 2, 3, 6, 7, 8],
    "dyrian": [0, 1, 2, 5, 6, 7, 11],
    "koptian": [0, 1, 4, 5, 6, 10, 11],
    "thocrian": [0, 3, 4, 5, 9, 10, 11],
    "danian": [0, 1, 5, 6, 7, 8, 11],
    "ionarian": [0, 4, 5, 6, 9, 10, 11],
    "dynian": [0, 1, 2, 5, 6, 7, 8],
    "zydian": [0, 1, 4, 5, 6, 7, 11],
    "zathian": [0, 3, 4, 5, 6, 10, 11],
    "radian": [0, 1, 2, 3, 7, 8, 9],
    "syptian": [0, 1, 5, 6, 7, 10, 11],
    "aeolyrian": [0, 1, 3, 5, 6, 7, 8],
    "gorian": [0, 2, 4, 5, 6, 7, 11],
    "aeolodian": [0, 2, 3, 4, 5, 9, 10],
    "doptian": [0, 1, 2, 3, 7, 8, 10],
    "zacrian": [0, 1, 5, 6, 8, 10, 11],
    "pagian": [0, 3, 4, 5, 6, 8, 10],
    "aeolythian": [0, 1, 2, 3, 5, 7, 9],
    "molian": [0, 1, 2, 4, 6, 8, 11],
    "mothian": [0, 2, 4, 6, 9, 10, 11],
    "aeranian": [0, 2, 4, 7, 8, 9, 10],
    "ragian": [0, 2, 5, 6, 7, 8, 10],
    "porian": [0, 1, 2, 4, 6, 8, 9],
    "lagian": [0, 2, 4, 5, 8, 9, 10],
    "golian": [0, 3, 4, 6, 8, 10, 11],
    "pynian": [0, 1, 2, 5, 6, 8, 10],
    "ranian": [0, 3, 4, 6, 9, 10, 11],
    "podian": [0, 2, 5, 6, 7, 8, 11],
    "ionothian": [0, 3, 4, 5, 6, 9, 10],
    "kanian": [0, 1, 2, 3, 6, 7, 9],
    "zylian": [0, 1, 2, 5, 6, 8, 11],
    "zarian": [0, 3, 4, 7, 8, 9, 10],
    "phrythian": [0, 1, 4, 5, 6, 7, 9],
    "rorian": [0, 3, 4, 5, 6, 8, 11],
    "bolian": [0, 1, 2, 3, 5, 8, 9],
    "kodian": [0, 2, 5, 6, 9, 10, 11],
    "tholian": [0, 3, 4, 7, 8, 9, 11],
    "stodian": [0, 1, 2, 4, 5, 8, 9],
    "ionygian": [0, 1, 4, 5, 8, 9, 10],
    "katathian": [0, 3, 4, 7, 8, 10, 11],
    "mixolocrian": [0, 1, 3, 4, 5, 8, 9],
    "sagian": [0, 2, 3, 4, 7, 8, 11],
    "aeolothian": [0, 1, 2, 5, 6, 9, 10],
    "socrian": [0, 1, 4, 5, 8, 9, 11],
    "laptian": [0, 3, 5, 6, 7, 8, 11]
}

dur_dict = {  # durations
    "dot_whole": 1.5 * measure,
    "whole": measure,
    "dot_half": .75 * measure,
    "half": .5 * measure,
    "dot_quarter": .375 * measure,
    "trip_half": (1/3) * measure,
    "quart": .25 * measure,
    "dot_eighth": .1875 * measure,
    "trip_quarter": (1 / 6) * measure,
    "eighth": .125 * measure,
    "dot_sixteenth": .1875 * measure,
    "trip_eighth": (1 / 12) * measure,
    "sixteenth": .0625 * measure,
    "dot_thirty": .09375 * measure,
    "thirty": .03125 * measure,
    "trip_thirty": (1 / 48) * measure
}

dur_dict_num = {
    0: dur_dict["dot_whole"],
    1: dur_dict["whole"],
    2: dur_dict["dot_half"],
    3: dur_dict["half"],
    4: dur_dict["dot_quarter"],
    5: dur_dict["trip_half"],
    6: dur_dict["quart"],
    7: dur_dict["dot_eighth"],
    8: dur_dict["trip_quarter"],
    9: dur_dict["eighth"],
    10: dur_dict["dot_sixteenth"],
    11: dur_dict["trip_eighth"],
    12: dur_dict["sixteenth"],
    13: dur_dict["dot_thirty"],
    14: dur_dict["thirty"],
    15: dur_dict["trip_thirty"],
}


vol_dict = {  # velocities in dB
    "ppp": -36.0,
    "pp": -23.9,
    "p": -16.9,
    "mp": -11.9,
    "mf": -8.0,
    "f": -4.9,
    "ff": -2.2,
    "fff": 0.0,
}

vol_dict_num = {
    0: vol_dict["ppp"],
    1: vol_dict["pp"],
    2: vol_dict["p"],
    3: vol_dict["mp"],
    4: vol_dict["mf"],
    5: vol_dict["f"],
    6: vol_dict["ff"],
    7: vol_dict["fff"]
}


def num_to_freq():
    """produces a list of all usable frequencies"""
    # A4 (440) is n = 49
    count = 0
    freq_list = []
    for n in range(0, 88):
        note_list = ["A", "A#/Bb", "B", "C", "C#/Db", "D", "D#/Eb", "E", "F", "F#/Gb", "G", "G#/Ab"]
        note_name_index = n % 12
        note_name = note_list[note_name_index]
        octave = None
        n += 1
        if n < 3:
            octave = 0
        elif n < 16:
            octave = 1
        elif n < 28:
            octave = 2
        elif n < 40:
            octave = 3
        elif n < 51:
            octave = 4
        elif n < 63:
            octave = 5
        elif n < 76:
            octave = 6
        elif n < 88:
            octave = 7
        elif n == 88:
            octave = 8
        freq = pow(pow(2, (1 / 12)), (n - 49.00)) * 440.00
        count += 1
        print("Key number: {}\nNote name: {}{}\nFrequency: {}\n".format(count, note_name, octave, freq))
        freq_list.append(freq)

    return freq_list


def play_scale(scale):
    result = AudioSegment.silent(duration=0)

    for each_note in scale_dict[scale]:
        gen = Sine(pitch_dict_note_num[each_note])
        sine = gen.to_audio_segment(duration=300).apply_gain(-3)
        sine = sine.fade_in(50).fade_out(50)
        result += sine

    return result


def get_notes(list_indexes):
    return_list = []
    for i in list_indexes:
        if isinstance(i, str) and i in pitch_dict:
            return_list.append(pitch_dict[i])
        elif isinstance(i, int) and i in pitch_dict_note_num:
            return_list.append(pitch_dict_note_num[i])
        else:
            return_list.append(None)
    return return_list

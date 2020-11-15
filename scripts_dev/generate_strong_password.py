import random
import string


def get_random_alphanumeric_string(length, with_punctuation=True, with_spaces=True):
    letters_and_digits = string.ascii_letters + string.digits
    if with_punctuation:
        letters_and_digits += string.punctuation
    if with_spaces:
        letters_and_digits += " "
    return ''.join((random.choice(letters_and_digits) for i in range(length)))


print("{}".format(get_random_alphanumeric_string(70)))

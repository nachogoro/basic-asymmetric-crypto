# Author: NachoGoro

from io_explain import explain, explaining_method
import math

def letter_to_number(letter, base):
    """
    Given a letter in the alphabet, it will return its value in the specified
    base (A: 0, B: 1, ...)

    Only bases 26 and 27 supported at the moment.
    """
    upper_case = letter.upper()

    if (len(upper_case) != 1
        or (not upper_case.isalpha()
            and not (base == 27 and upper_case == 'Ñ'))):
        # Not a letter
        return None

    # It's a letter
    if upper_case == 'Ñ':
        return 14
    else:
        result = ord(upper_case) - ord('A')
        if base == 27 and result > 13:
            result += 1

        return result


def number_to_letter(number, base):
    """
    Given a number, it will return its corresponding letter in the given base.
    base (0: A, 1: B, ...)

    Only bases 26 and 27 supported at the moment.
    """
    if not 0 <= number < base:
        # Not in valid range
        return None

    index = ord('A') + number

    if base == 27:
        if number == 14:
            return 'Ñ'
        elif number > 14:
            index -= 1

    return chr(index)


def validate_message(msg, base):
    """
    Validates that a message only contains alphabetic characters in the
    specified base.

    Only bases 26 and 27 supported at the moment.
    """
    if base == 26:
        return msg.isalpha()

    for c in msg:
        if not (c.isalpha() or c.upper() == 'Ñ'):
            return False
    return True


@explaining_method
def get_as_number(msg, base, cache=None):
    """
    Given an alphabetic string, it will encode it in the specified base as a
    number.

    Only bases 26 and 27 supported at the moment.
    """
    if type(msg) is int:
        return msg

    if cache and msg in cache:
        return cache[msg]

    as_numbers = [letter_to_number(c, base) for c in msg]
    result = 0

    explain_rep = list()

    for i, n in enumerate(as_numbers):
        result += n * base**(len(as_numbers) - 1 - i)

        explain_rep.append('%s*%d^%d' % (n, base, len(as_numbers) - 1 - i))

    explain(
        '%s can be expressed (in base %d) as: %s = %d'
        % (msg, base, ' + '.join(explain_rep), result))

    if cache:
        cache[msg] = result

    return result


@explaining_method
def get_as_string(number, base, cache=None):
    """
    Given a number in the specified base, it will return its string
    representation.

    Only bases 26 and 27 supported at the moment.
    """
    if type(number) is str:
        return number

    if cache:
        cached_result = next((key for key, val in cache.items() if val == number), None)
        if cached_result:
            return cached_result

    n = number
    letters_in_reverse = list()
    while n > 0:
        value = n % base
        letters_in_reverse.append(number_to_letter(value, base))
        n = (n - value) // base

    if not letters_in_reverse:
        result = 'A'
    else:
        result = ''.join(letters_in_reverse[::-1])

    num_rep = list()
    letter_rep = list()
    if len(letters_in_reverse) == 0:
        explain('%d = 0 --> A' % number)
    else:
        for i in range(0, len(letters_in_reverse)):
            num_rep.append(
                '%d*%d^%d'
                % (letter_to_number( letters_in_reverse[-(i+1)], base),
                    base,
                    len(letters_in_reverse) - 1 - i))

            letter_rep.append(
                '%s*%d^%d' % (letters_in_reverse[-(i+1)],
                                base,
                                len(letters_in_reverse) - 1 - i))

        explain('%d can be expressed (in base %d) as: %d = %s --> %s --> %s'
                % (number, base, number, ' + '.join(num_rep),
                   ' + '.join(letter_rep), result))

    if cache:
        cache[result] = number
    return result


def compute_block_size(n, base):
    """
    Returns the block size (in characters) associated with a certain number.
    """
    return int(math.log(n, base))


def get_msg_chunks(msg, base, n, round_down=True):
    """
    Splits a message in a certain base in equally-sized chunks.

    If round_down is set to True, the chunks will be as large as possible while
    keeping their number representation below n.

    If round_down is set to False, the chunks will be one character longer than
    what would be needed to ensure their number representation would be below
    n.
    """
    block_size = compute_block_size(n, base)

    if not round_down:
        block_size += 1

    if block_size >= len(msg):
        return [msg]

    return [msg[i:i+block_size] for i in range(0, len(msg), block_size)]

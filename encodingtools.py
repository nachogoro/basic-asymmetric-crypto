# Author: NachoGoro

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


def get_as_number(msg, base, debug=False):
    """
    Given an alphabetic string, it will encode it in the specified base as a
    number.

    If debug is set to True, it will print the steps followed to reach the result.

    Only bases 26 and 27 supported at the moment.
    """
    as_numbers = [letter_to_number(c, base) for c in msg]
    result = 0

    debug_rep = list()

    for i, n in enumerate(as_numbers):
        result += n * base**(len(as_numbers) - 1 - i)

        if debug:
            debug_rep.append('%s*%d^%d' % (n, base, len(as_numbers) - 1 - i))

    if debug:
        print(
            '%s can be expressed (in base %d) as: %s = %d'
            % (msg, base, ' + '.join(debug_rep), result))

    return result


def get_as_string(number, base, debug=False):
    """
    Given a number in the specified base, it will return its string
    representation.

    If debug is set to True, it will print the steps followed to reach the result.

    Only bases 26 and 27 supported at the moment.
    """
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

    if debug:
        debug_num_rep = list()
        debug_letter_rep = list()
        if len(letters_in_reverse) == 0:
            print('%d = 0 --> A' % number)
        else:
            for i in range(0, len(letters_in_reverse)):
                debug_num_rep.append(
                    '%d*%d^%d'
                    % (letter_to_number( letters_in_reverse[-(i+1)], base),
                        base,
                        len(letters_in_reverse) - 1 - i))

                debug_letter_rep.append(
                    '%s*%d^%d' % (letters_in_reverse[-(i+1)],
                                  base,
                                  len(letters_in_reverse) - 1 - i))

            print('%d can be expressed (in base %d) as: %d = %s --> %s --> %s'
                  % (number, base, number, ' + '.join(debug_num_rep),
                     ' + '.join(debug_letter_rep), result))

    return result


def get_msg_chunks(msg, base, n, round_down=True):
    """
    Splits a message in a certain base in equally-sized chunks.

    If round_down is set to True, the chunks will be as large as possible while
    keeping their number representation below n.

    If round_down is set to False, the chunks will be one character longer than
    what would be needed to ensure their number representation would be below
    n.
    """
    chunk_size = int(math.log(n, base))

    if not round_down:
        chunk_size += 1

    if chunk_size >= len(msg):
        return [msg]

    return [msg[i:i+chunk_size] for i in range(0, len(msg), chunk_size)]

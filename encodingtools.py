import math

def letter_to_number(letter, base):
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
    if base == 26:
        return msg.isalpha()

    for c in msg:
        if not (c.isalpha() or c.upper() == 'Ñ'):
            return False
    return True


def get_as_number(msg, base, debug=False):
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
    # TODO add debug
    letters_in_reverse = list()
    while number > 0:
        value = number % base
        letters_in_reverse.append(number_to_letter(value, base))
        number = (number - value) // base

    if not letters_in_reverse:
        return 'A'

    return ''.join(letters_in_reverse[::-1])


def get_msg_chunks(msg, base, n):
    chunk_size = int(math.log(n, base))

    if chunk_size >= len(msg):
        return [msg]

    return [msg[i:i+chunk_size] for i in range(0, len(msg), chunk_size)]

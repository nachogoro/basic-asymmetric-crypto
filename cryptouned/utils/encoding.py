# Author: NachoGoro

from cryptouned.utils.io_explain import explain, explaining_method


def letter_to_number(letter: str, base: int) -> int:
    """
    Convert a letter to its corresponding numerical value in a specified base.

    The conversion is based on the position in the alphabet (e.g., A: 0, B: 1, ...).
    Supports base 26 (English alphabet) and base 27 (Spanish alphabet without accents).

    Parameters:
    letter (str): The letter to be converted.
    base (int): The base of the alphabet (26 or 27).

    Returns:
    int: The numerical value of the letter in the specified base.

    Raises:
    ValueError: If the letter is not part of the alphabet.
    """

    upper_case = letter.upper()

    if (len(upper_case) != 1
            or (not upper_case.isalpha()
                and not (base == 27 and upper_case == 'Ñ'))):
        # Not a letter
        raise ValueError(f"{letter} is not part of the base-{base} alphabet")

    # It's a letter
    if upper_case == 'Ñ':
        return 14
    else:
        result = ord(upper_case) - ord('A')
        if base == 27 and result > 13:
            result += 1

        return result


def number_to_letter(number: int, base: int) -> str:
    """
    Convert a number to its corresponding letter in a given base.

    The conversion follows the alphabetical order (0: A, 1: B, ...).
    Supports base 26 (English alphabet) and base 27 (Spanish alphabet without accents).

    Parameters:
    number (int): The number to be converted.
    base (int): The base of the alphabet (26 or 27).

    Returns:
    str: The letter corresponding to the given number in the specified base.

    Raises:
    ValueError: If the number is not in the range [0, base).
    """

    if not 0 <= number < base:
        # Not in valid range
        raise ValueError(f"{number} is not in [0, {base}) range")

    index = ord('A') + number

    if base == 27:
        if number == 14:
            return 'Ñ'
        elif number > 14:
            index -= 1

    return chr(index)


def validate_message(msg: str, base: int) -> bool:
    """
    Check if a message contains only valid alphabetic characters for a specified base.

    Validates that the message is composed of letters that are valid in the
    given base. Currently supports base 26 (English alphabet) and base 27
    (Spanish alphabet including 'Ñ').

    Parameters:
    msg (str): The message to be validated.
    base (int): The base of the alphabet (26 or 27).

    Returns:
    bool: True if the message is valid for the specified base, False otherwise.
    """

    if base == 26:
        return msg.isalpha()

    for c in msg:
        if not (c.isalpha() or c.upper() == 'Ñ'):
            return False
    return True


@explaining_method
def get_as_number(msg: str | int, base: int, cache: dict = None) -> int:
    """
    Encode an alphabetic string into a number using the specified base.

    Converts each letter of the string to its numerical value and encodes the
    entire string as a single number in the given base. Supports base 26
    (English) and base 27 (Spanish including 'Ñ'). Can optionally use a cache
    to store and retrieve previously computed values.

    Parameters:
    msg (str | int): The message to be encoded or an integer to be returned as is.
    base (int): The base of the alphabet (26 or 27).
    cache (dict, optional): A cache dictionary to store/retrieve previously computed values.

    Returns:
    int: The numerical representation of the string in the specified base.
    """

    if type(msg) is int:
        return msg

    if cache and msg in cache:
        return cache[msg]

    as_numbers = [letter_to_number(c, base) for c in msg]
    result = 0

    explain_rep = list()

    for i, n in enumerate(as_numbers):
        result += n * base ** (len(as_numbers) - 1 - i)

        explain_rep.append('%s*%d^%d' % (n, base, len(as_numbers) - 1 - i))

    explain(
        '%s can be expressed (in base %d) as: %s = %d'
        % (msg, base, ' + '.join(explain_rep), result))

    if cache:
        cache[msg] = result

    return result


@explaining_method
def get_as_string(msg: int | str, base: int, cache: dict = None) -> str:
    """
    Decode a number into its string representation using the specified base.

    Converts a number into a string where each digit of the number is
    represented by a letter in the given base. Supports base 26 (English) and
    base 27 (Spanish including 'Ñ'). Can optionally use a cache to store and
    retrieve previously computed values.

    Parameters:
    msg (int | str): The number to be decoded or a string to be returned as is.
    base (int): The base of the alphabet (26 or 27).
    cache (dict, optional): A cache dictionary to store/retrieve previously computed values.

    Returns:
    str: The alphabetic representation of the number in the specified base.
    """

    if type(msg) is str:
        return msg

    if cache:
        cached_result = next((key for key, val in cache.items() if val == msg), None)
        if cached_result:
            return cached_result

    n = msg
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
        explain('%d = 0 --> A' % msg)
    else:
        for i in range(0, len(letters_in_reverse)):
            num_rep.append(
                '%d*%d^%d'
                % (letter_to_number(letters_in_reverse[-(i + 1)], base),
                   base,
                   len(letters_in_reverse) - 1 - i))

            letter_rep.append(
                '%s*%d^%d' % (letters_in_reverse[-(i + 1)],
                              base,
                              len(letters_in_reverse) - 1 - i))

        explain('%d can be expressed (in base %d) as: %d = %s --> %s --> %s'
                % (msg, base, msg, ' + '.join(num_rep),
                   ' + '.join(letter_rep), result))

    if cache:
        cache[result] = msg
    return result

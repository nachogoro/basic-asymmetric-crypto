from cryptouned.utils import encoding
from cryptouned.utils.io_explain import explaining_method, explain

def sum_hash(msg, base):
    """
    Returns the arithmetic sum of the integer representation of the letters in the string (mod base)
    """
    result = sum((encoding.letter_to_number(c, base) for c in msg)) % base

    formatted_chars = [f'{c}' for c in msg]
    numeric_list = [encoding.letter_to_number(c, base) for c in msg]
    explain(f'hash({msg}) = ({" + ".join(formatted_chars)}) mod {base}= '
            f'({" + ".join((str(n) for n in numeric_list))}) mod {base} = {result}')

    return result

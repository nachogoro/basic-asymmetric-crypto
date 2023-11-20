from cryptouned.utils import encoding
from cryptouned.utils.io_explain import explaining_method, explain

@explaining_method
def sum_hash(msg: str, base: int) -> int:
    """
    Calculate the hash of a message by summing the integer values of its characters.

    This function computes the hash as the arithmetic sum of the integer representations
    of the letters in the string, modulo the specified base. Each character in the message
    is first converted to its corresponding integer value in the given base, and then all
    these values are summed up to get the hash.

    The function uses an explaining method decorator to provide an optional detailed
    explanation of the process.

    Parameters:
    msg (str): The message to be hashed.
    base (int): The base used for calculating the hash. Also, the value with which the sum is moduloed.

    Returns:
    int: The calculated hash value of the message.
    """
    result = sum((encoding.letter_to_number(c, base) for c in msg)) % base

    formatted_chars = [f'{c}' for c in msg]
    numeric_list = [encoding.letter_to_number(c, base) for c in msg]
    explain(f'hash({msg}) = ({" + ".join(formatted_chars)}) mod {base}= '
            f'({" + ".join((str(n) for n in numeric_list))}) mod {base} = {result}')

    return result

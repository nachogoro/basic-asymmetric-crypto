from cryptouned.utils.io_explain import explain, explaining_method
from cryptouned.utils.elgamal_types import EncryptedPair, SignedPair
from cryptouned.utils import encoding
from math import floor, log


@explaining_method
def get_block_size(n: int, base: int) -> int:
    """
    Calculate the block size for a given modulo and base.

    Determines the maximum size of blocks that can be used for cryptographic
    operations based on the provided modulo `n` and the base of the encoding.

    Parameters:
    n: The modulo used in the cryptographic operation.
    base: The base of the encoding.

    Returns:
    The calculated block size.
    """

    result = floor(log(n, base))
    explain(f'Block size for {n} in base {base} is floor(log{base}({n})) = {result}')
    return result


@explaining_method
def pad(msg: str, length: int) -> str:
    """
    Pad a message to a specified length by adding 'A's to the left.

    If the message is shorter than the desired length, 'A's are added to the
    left of the message until it reaches the specified length.

    Parameters:
    msg: The message to be padded.
    length: The desired length of the padded message.

    Returns:
    The padded message.
    """

    result = msg.rjust(length, 'A')
    explain(f'{msg} padded to {length} characters is {result}')
    return result


def split_in_blocks_of_size(msg: str, block_size: int) -> list[str]:
    """
    Split a message into blocks of a specified size.

    Parameters:
    msg (str): The message to be split.
    block_size (int): The size of each block.

    Returns:
    A list of message blocks, each of the specified size.
    """
    return [msg[i:i + block_size] for i in range(0, len(msg), block_size)]


@explaining_method
def split_message_in_blocks(msg: str | int, n: int, base: int) -> list[str | int]:
    """
    Split a message or number into blocks suitable for encryption or decryption.

    For strings, it splits the message into blocks based on the block size determined
    by `n` and `base`. For integers, it first converts the number into a string
    representation and then splits it into blocks.

    Parameters:
    msg: The message or number to be split.
    n: The modulo used in the cryptographic operation.
    base: The base of the encoding.

    Returns:
    A list of blocks obtained from the message or number.
    """

    if type(msg) is str:
        block_size = get_block_size(n, base)
        explain(f'To transform a string using modulo {n}, we must split it '
                f'into blocks of at most {block_size} characters')

        if len(msg) <= block_size:
            explain(f'Since {msg} is only {len(msg)} characters long, it does '
                    'not need to be split into blocks')
            return [msg]

        blocks = split_in_blocks_of_size(msg, block_size)
        explain(f'{msg} is split into {blocks}')
        return blocks

    if type(msg) is int:
        explain(
            f'To transform a number using modulo {n}, we have to guarantee that it is a number between 0 and {n - 1}')
        if msg < n:
            explain(f'Since {msg} is already in the range [0, {n - 1}], we don\'t have to split it')
            return [msg]

        explain(f'Since {msg} is larger than {n - 1}, have to split it somehow')
        explain(
            f'The method we\'ll use is converting the number into a string base {base} and split that in blocks')
        explain(f'NOTE: This may not be the way it is expected to be done in the subject')
        msg_str = encoding.get_as_string(msg, n)
        blocks = split_message_in_blocks(msg_str, n, base)
        explain('Now we must convert those blocks of string back into integers')

        result = []
        for block in blocks:
            result.append(encoding.get_as_number(block, base))
        explain(f'{msg} is split into {result}')
        return result


@explaining_method
def split_cryptogram_in_blocks(msg: str | EncryptedPair | int, n: int, base: int) -> list[str | EncryptedPair | int]:
    """
    Split a cryptogram into blocks for decryption.

    Depending on the type of `msg`, it splits the cryptogram into blocks of
    appropriate size for decryption. For strings, it uses knowledge of the
    padding scheme. For EncryptedPair objects, it also takes into account
    the block size and padding. For integers, it assumes the integer is the
    numeric representation of a string.

    Parameters:
    msg (str | EncryptedPair | int): The cryptogram to be split into blocks.
    n (int): The modulo used in the cryptographic operation.
    base (int): The base of the encoding.

    Returns:
    list[str | EncryptedPair | int]: A list of blocks obtained from the cryptogram.
    """

    if type(msg) is str:
        explain(f'To split a cryptogram which was encrypted using modulo {n}, '
                f'we use the knowledge that the sender padded each block to '
                f'one letter more than the block size of {n}')

        padded_block_size = get_block_size(n, base) + 1
        explain(f'So we know each block of the cryptogram is padded to {padded_block_size} characters')

        if len(msg) <= padded_block_size:
            explain(f'Since {msg} is only {len(msg)} characters long, it does '
                    'not need to be split into blocks, since it is a single crypto block')
            return [msg]

        explain(
            f'We need to split the cryptogram {msg} into blocks of {padded_block_size} characters')
        blocks = split_in_blocks_of_size(msg, padded_block_size)
        explain(f'{msg} is split into {blocks}')
        return blocks

    if type(msg) is EncryptedPair:
        explain(f'To split a cryptogram which was encrypted using modulo {n}, '
                f'we use the knowledge that the sender padded each block to '
                f'one letter more than the block size of {n}')

        padded_block_size = get_block_size(n, base) + 1
        explain(f'So we know each block of the cryptogram is padded to {padded_block_size}')

        msg_pair = msg
        if (any(len(s) > padded_block_size for s in (msg_pair.g_v, msg_pair.m_g_v_b))
                and (len(msg_pair.g_v) != len(msg_pair.m_g_v_b))):
            explain(f'Padding in incorrect in the cryptogram: both parts of '
                    'the message should be of equal length if any of them is '
                    'larger than the maximum length of a single block size')
            raise ValueError("Invalid lengths in ElGamal cryptogram")

        if len(msg_pair.g_v) <= padded_block_size:
            explain(f'Since both parts of the cryptogram are shorter than '
                    f'{padded_block_size} characters, there is no need to '
                    f'split the cryptogram')
            return [msg_pair]

        explain(f'We need to split the cryptogram into blocks of {padded_block_size} characters')

        g_v_blocks = split_in_blocks_of_size(msg_pair.g_v, padded_block_size)
        m_g_v_b_blocks = split_in_blocks_of_size(msg_pair.m_g_v_b, padded_block_size)

        blocks = [EncryptedPair(g_v_blocks[i], m_g_v_b_blocks[i])
                  for i in range(len(g_v_blocks))]

        explain(f'({msg_pair.g_v}, {msg_pair.m_g_v_b}) is split into '
                f'{[(t.g_v, t.m_g_v_b) for t in blocks]}')

        return blocks

    if type(msg) is int:
        explain(
            f'To transform a number using modulo {n}, we have to guarantee that it is a number between 0 and {n - 1}')
        if msg < n:
            explain(f'Since {msg} is already in the range [0, {n - 1}], we don\'t have to split it')
            return [msg]

        explain(f'Since {msg} is larger than {n}, we will assume that it is '
                'the numeric representation of a string in order to split it')

        msg_as_string = encoding.get_as_string(msg, base)

        explain(f'We know the sender padded each block to one letter more than '
                f'the block size of {n}')

        padded_block_size = get_block_size(n, base) + 1

        explain(
            f'We need to split the cryptogram {msg_as_string} into blocks of {padded_block_size} characters')
        blocks = split_in_blocks_of_size(msg, padded_block_size)
        explain(f'{msg_as_string} is split into {blocks}')
        explain('Now, we encode each chunk as an number again')

        result = [encoding.get_as_number(block, base) for block in blocks]
        return result


@explaining_method
def assemble_cryptogram(blocks: list[str | EncryptedPair | int], n: int, base: int, cache: dict = None) -> str | EncryptedPair | int:
    """
    Assemble a series of cipher blocks into a single cryptogram.

    This method combines several blocks of encrypted data into a single
    cryptogram. It handles different types of blocks, including strings,
    EncryptedPair objects, and integers, considering the block size and padding.

    Parameters:
    blocks (list[str | EncryptedPair | int]): The list of encrypted blocks to be assembled.
    n (int): The modulo used in the cryptographic operation.
    base (int): The base of the encoding.
    cache (dict): A cache for previously computed string-to-number conversions.

    Returns:
    str | EncryptedPair | int: The assembled cryptogram.
    """

    if cache is None:
        cache = dict()

    if type(blocks[0]) is str:
        # We must assemble a list of string blocks, for encryption
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The cryptogram simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the message into blocks, we need to '
                'assemble the encrypted blocks to form the cryptogram')
        explain('The receiver will need to split the cryptogram back into the '
                'same blocks we are assembling, so we need to pad them all to '
                'the same length so there is no doubt about where to split the '
                'cryptogram')
        explain('We will use the length of the largest possible encrypted '
                'block, which is one more than the block size')
        padded_block_size = get_block_size(n, base) + 1
        explain(f'We pad all blocks adding \'A\' to the left up to {padded_block_size} characters')

        result = [pad(block, padded_block_size) for block in blocks]
        explain('Finally, we concatenate all padded blocks to obtain our cryptogram')
        assembled = "".join(result)
        explain(f'Since our padded crypto blocks are {result}, our cryptogram is {assembled}')
        return assembled

    if type(blocks[0]) is EncryptedPair:
        # We must assemble a list of ElGamal encrypted blocks
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The cryptogram simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the message into blocks, we need to '
                'assemble the encrypted blocks to form the cryptogram')
        explain('The receiver will need to split the cryptogram back into the '
                'same blocks we are assembling, so we need to pad them all to '
                'the same length so there is no doubt about where to split the '
                'cryptogram')
        explain('We will use the length of the largest possible encrypted '
                'block, which is one more than the block size')
        padded_block_size = get_block_size(n, base) + 1
        explain(f'We pad all blocks adding \'A\' to the left up to {padded_block_size} characters')

        padded_blocks = []
        for block in blocks:
            padded_block = EncryptedPair(pad(block.g_v, padded_block_size, explain=False),
                                         pad(block.m_g_v_b, padded_block_size, explain=False))
            explain(f'{block} gets padded to {padded_block}')
            padded_blocks.append(padded_block)

        explain('Finally, we concatenate all padded blocks to obtain our cryptogram')
        result = EncryptedPair(g_v=''.join([c.g_v for c in padded_blocks]),
                               m_g_v_b=''.join([c.m_g_v_b for c in padded_blocks]))
        explain(
            f'Since our padded crypto blocks are [{",".join(str(b) for b in padded_blocks)}], our cryptogram is '
            f'{result}')
        return result

    if type(blocks[0]) is int:
        # We must assemble a list of int blocks, for encryption
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The cryptogram simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the message into blocks, we need to '
                'assemble the encrypted blocks to form the cryptogram')
        explain('NOTE: There is no agreed upon method in the subject for '
                'splitting and assembling numbers, so we will convert them to '
                'strings and work with them')

        as_str = [encoding.get_as_string(block, base, cache=cache) for block in blocks]
        str_result = assemble_cryptogram(as_str, base, n, cache=cache)
        explain('Since we assembled blocks of integers, we want the result as an integer')
        return encoding.get_as_number(str_result, base, cache)


@explaining_method
def assemble_message(blocks: list[str | int], n: int, base: int, cache: dict = None) -> str | int:
    """
    Assemble a series of clear text blocks into a single message.

    Combines multiple blocks of decrypted data into a single clear text message.
    It handles different types of blocks, including strings and integers,
    considering the block size and padding requirements.

    Parameters:
    blocks (list[str | int]): The list of decrypted blocks to be assembled.
    n (int): The modulo used in the cryptographic operation.
    base (int): The base of the encoding.
    cache (dict): A cache for previously computed values.

    Returns:
    str | int: The assembled clear text message.
    """
    if cache is None:
        cache = dict()

    if type(blocks[0]) is str:
        # We must assemble a list of string blocks, for decryption
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The message simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the cryptogram into blocks, we need to '
                'assemble the decrypted blocks to form the message')
        explain('The sender split the message in blocks of a given length '
                '(with the exception of the last block). That length is the '
                'block size determined by {n}')
        block_size = get_block_size(n, base)
        explain(f'We pad all blocks (but the last one) adding \'A\' to the left up to {block_size} '
                'characters')

        result = [pad(block, block_size) for block in blocks[:-1]] + [blocks[-1]]
        explain('Finally, we concatenate all padded blocks to obtain our message')
        assembled = "".join(result)
        explain(f'Since our padded blocks are {result}, our message is {assembled}')
        return assembled

    if type(blocks[0]) is int:
        # We must assemble a list of int blocks, for decryption
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The message simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the cryptogram into blocks, we need to '
                'assemble the encrypted blocks to form the message')
        explain('NOTE: There is no agreed upon method in the subject for '
                'splitting and assembling numbers, so we will convert them to '
                'strings and work with them')

        as_str = [encoding.get_as_string(block, base, cache=cache) for block in blocks]
        str_result = assemble_message(as_str, base, n, cache=cache)
        explain('Since we assembled blocks of integers, we want the result as an integer')
        return encoding.get_as_number(str_result, base, cache)


@explaining_method
def assemble_signature(blocks: list[str | SignedPair], n: int, base: int) -> str | SignedPair:
    """
    Assemble a series of blocks into a single digital signature.

    This method combines several blocks of a digital signature into a single
    signature string. It handles different types of blocks, including strings
    and SignedPair objects, considering the block size and padding requirements.

    Parameters:
    blocks (list[str | SignedPair]): The list of signature blocks to be assembled.
    n (int): The modulo used in the cryptographic operation.
    base (int): The base of the encoding.

    Returns:
    str | SignedPair: The assembled digital signature.
    """

    if type(blocks[0]) is str:
        # We must assemble a list of string blocks, for encryption
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The signature simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the message into blocks, we need to '
                'assemble the encrypted blocks to form the signature')
        explain('The receiver will need to split the signature back into the '
                'same blocks we are assembling, so we need to pad them all to '
                'the same length so there is no doubt about where to split the '
                'signature')
        explain('We will use the length of the largest possible encrypted '
                'block, which is one more than the block size')
        padded_block_size = get_block_size(n, base) + 1
        explain(f'We pad all blocks adding \'A\' to the left up to {padded_block_size} characters')

        result = [pad(block, padded_block_size) for block in blocks]
        explain('Finally, we concatenate all padded blocks to obtain our signature')
        assembled = "".join(result)
        explain(f'Since our padded blocks are {result}, our signature is {assembled}')
        return assembled

    elif type(blocks[0]) is SignedPair:
        # We must assemble a list of ElGamal signed blocks
        if len(blocks) == 1:
            explain('Since we only have a single block, there is no need to assemble or pad')
            explain(f'The signature simply is {blocks[0]}')
            return blocks[0]

        explain('Since we had to split the message into blocks, we need to '
                'assemble them to form the signature')
        explain('The receiver will need to split the signature back into the '
                'same blocks we are assembling, so we need to pad them all to '
                'the same length so there is no doubt about where to split the '
                'cryptogram')
        explain('We will use the length of the largest possible signed '
                'block, which is one more than the block size')
        padded_block_size = get_block_size(n, base) + 1
        explain(f'We pad all blocks adding \'A\' to the left up to {padded_block_size} characters')

        padded_blocks = []
        for block in blocks:
            padded_block = SignedPair(r=pad(block.r, padded_block_size, explain=False),
                                      s=pad(block.s, padded_block_size, explain=False))
            explain(f'{block} gets padded to {padded_block}')
            padded_blocks.append(padded_block)

        explain('Finally, we concatenate all padded blocks to obtain our signature')
        result = SignedPair(r=''.join([c.r for c in padded_blocks]),
                            s=''.join([c.s for c in padded_blocks]))
        explain(
            f'Since our padded blocks are [{",".join(str(b) for b in padded_blocks)}], our signature is '
            f'{result}')
        return result

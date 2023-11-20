# Author: NachoGoro
from typing import Callable

from cryptouned.utils import modmath, encoding
from cryptouned.utils.blockmgr import (split_message_in_blocks, split_cryptogram_in_blocks,
                                       assemble_cryptogram, assemble_message, assemble_signature)
from cryptouned.utils.io_explain import explain, explaining_method


class Agent:
    """
    Class representing one side in an RSA communication.
    """

    def __init__(self,
                 name: str,
                 p: int | None = None,
                 q: int | None = None,
                 n: int | None = None,
                 phi_n: int | None = None,
                 e: int | None = None,
                 d: int | None = None):
        """
        Initialize an Agent for RSA communication.

        Parameters:
        name (str): Name of the agent for identification.
        p (int | None): One of the two prime factors of n, along with q.
        q (int | None): One of the two prime factors of n, along with p.
        n (int | None): Large number, product of p and q.
        phi_n (int | None): Result of Euler's totient function applied to n ((p-1)*(q-1)).
        e (int | None): Public key of the agent.
        d (int | None): Private key of the agent.
        """

        self.name = name
        self.p = p
        self.q = q
        self.n = n
        self.phi_n = phi_n
        self.e = e
        self.d = d

        if n and p and q and (p * q != n):
            raise Exception('Inconsistent values n, p and q ({} != {}*{})'
                            .format(n, p, q))

        if p and q and phi_n and (phi_n != (p - 1) * (q - 1)):
            raise Exception(
                'Inconsistent values phi_n, p and q ({} != ({}-1)*({}-1))'
                .format(phi_n, p, q))

        tmp_phi_n = None

        if (p and q):
            tmp_phi_n = (p - 1) * (q - 1)
        elif phi_n:
            tmp_phi_n = phi_n

        if tmp_phi_n:
            if e and d and ((e * d % tmp_phi_n) != 1):
                raise Exception(
                    'Inconsistent values: e is not the inverse of d in phi_n')

    def get_n(self):
        """
        Returns n
        """
        if not self.n and self.p and self.q:
            self.n = self.p * self.q

        return self.n

    def get_phi_n(self):
        """
        Returns phi(n), i.e. (p-1)*(q-1)
        """
        if not self.phi_n and self.p and self.q:
            self.phi_n = (self.p - 1) * (self.q - 1)

        return self.phi_n

    def get_private_key(self):
        """
        Returns the private key of the agent
        """
        if not self.d and self.e and self.get_phi_n():
            # Private key can be derived from public key and phi_n
            self.d = modmath.inverse(self.e, self.get_phi_n(), False)

        return self.d

    def get_public_key(self):
        """
        Returns the public key of the agent
        """
        if not self.e and self.d and self.get_phi_n():
            # Public key can be derived from private key and phi_n
            self.e = modmath.inverse(self.d, self.get_phi_n())

        return self.e


@explaining_method
def encrypt(msg: str, sender: Agent, receiver: Agent, base: int = 27) -> str | None:
    """
    Encrypt a message using RSA.

    Parameters:
    msg (str): The message to be encrypted.
    sender (Agent): The agent sending the message. Irrelevant for encryption.
    receiver (Agent): The agent receiving the message.
    base (int): The base of the alphabet used for encoding (26 for English, 27 for Spanish).

    Returns:
    str | None: The encrypted message if successful, or None if encryption fails.
    """

    cached_conversions = dict()

    # In order to encrypt a message we just need the public key and n of the
    # receiver
    if not receiver.get_public_key() or not receiver.get_n():
        explain('Public key or n of %s is unknown' % str(receiver.name))
        return None

    encrypted_numbers = _transform(
        msg=msg,
        key=receiver.get_public_key(),
        n=receiver.get_n(),
        decryption=False,
        base=base,
        cache=cached_conversions)

    explain('In order to get the cryptogram, we represent the blocks as strings')
    encrypted_blocks = [encoding.get_as_string(block, base)
                        for block in encrypted_numbers]

    return assemble_cryptogram(encrypted_blocks,
                               receiver.get_n(),
                               base,
                               cache=cached_conversions)


@explaining_method
def decrypt(msg: str, sender: Agent, receiver: Agent, base: int = 27) -> str | None:
    """
    Decrypt a message using RSA.

    Parameters:
    msg (EncryptedPair): The encrypted message to be decrypted.
    sender (Agent): The agent who sent the message. Irrelevant for decryption.
    receiver (Agent): The agent who will decrypt the message.
    base (int): The base of the alphabet used for encoding (26 for English, 27 for Spanish).

    Returns:
    str | None: The decrypted message if successful, or None if decryption fails.
    """

    cached_conversions = dict()
    # In order to decrypt a message we just need the private key and n of
    # the receiver
    if not receiver.get_private_key() or not receiver.get_n():
        explain('Private key or n of %s is unknown' % str(receiver.name))
        return None

    decrypted_numbers = _transform(msg=msg, key=receiver.get_private_key(),
                                   n=receiver.get_n(), cache=cached_conversions,
                                   base=base, decryption=True)

    explain('In order to get the clear message, we represent the blocks as strings')
    decrypted_blocks = [encoding.get_as_string(block, base)
                        for block in decrypted_numbers]

    return assemble_message(decrypted_blocks,
                            receiver.get_n(),
                            base,
                            cache=cached_conversions)


@explaining_method
def sign(msg: str,
         sender: Agent,
         receiver: Agent,
         base: int = 27,
         hash_fn: Callable[[str, int], int] | None = None) -> str | None:
    """
    Sign a message using RSA.

    The message will be signed by the sender and encrypted for the receiver.

    Parameters:
    msg (str): The message to be signed.
    sender (Agent): The agent signing the message.
    receiver (Agent): The agent who will receive the signed message.
    base (int): The base of the alphabet used for encoding (26 for English, 27 for Spanish).
    hash_fn (Callable[[str, int], int] | None): Optional hash function to apply to the message before signing.

    Returns:
    SignedPair | None: The signed message if successful, or None if signing fails.
    """

    cached_conversions = dict()
    # In order to sign a message we need the public key and n of the
    # receiver and the private key and n of the sender
    if not receiver.get_public_key() or not receiver.get_n():
        explain('Public key or n of %s is unknown' % str(receiver.name))
        return None

    if not sender.get_private_key() or not sender.get_n():
        explain('Private key or n of %s is unknown' % str(sender.name))
        return None

    # We first encrypt with the private key of the sender and the result
    # with the public key of the receiver
    msg = msg.upper()

    msg_to_sign = msg

    if hash_fn:
        # A hash has been specified
        explain('First of all, we need to hash the message')

        msg_to_sign = hash_fn(msg, base)

        explain(f'hash({msg}) = {msg_to_sign}')
    else:
        explain('No hash function has been specified, so we will sign the '
                'message as-is')

    explain('\nFirst step is to compute the rubric of the message (i.e. '
            'encrypting the message with the sender\'s private key)')

    rubric_chunks = _transform(msg=msg_to_sign, key=sender.get_private_key(),
                               n=sender.get_n(), base=base, decryption=False)

    explain(f'\nWe obtain the following chunks for the rubric: {rubric_chunks}')

    explain('\nWe now need to encrypt each chunk of the rubric '
            'individually with the receiver\'s public key for security. '
            'That is the signature')

    signed_numbers = list()

    for chunk in rubric_chunks:
        explain(f'\nEncrypting chunk {chunk}:')

        signature_block = _transform(msg=chunk,
                                     key=receiver.get_public_key(),
                                     n=receiver.get_n(),
                                     base=base,
                                     cache=cached_conversions)

        signed_numbers.append(*signature_block)

    explain('In order to get the signature, we represent the signature blocks as strings')
    signature_blocks = [encoding.get_as_string(block, base, cache=cached_conversions)
                        for block in signed_numbers]

    return assemble_signature(signature_blocks,
                              receiver.get_n(),
                              base)


@explaining_method
def _transform(msg: str | int,
               key: int,
               n: int,
               base: int,
               decryption: bool = False,
               cache: dict = None) -> list[int]:
    """
    Transform a message for encryption, decryption, or signing using RSA.

    Parameters:
    msg (str | int): The message to transform.
    key (int): The key used for the transformation.
    n (int): The modulo used for the RSA operations.
    base (int): The base of the alphabet used for encoding (26 for English, 27 for Spanish).
    decryption (bool): Specifies whether the transformation is for decryption.
    cache (dict): Optional cache for previously computed values.

    Returns:
    list[int]: The transformed message blocks as integers.
    """

    if cache is None:
        cache = dict()

    if type(msg) is str and not encoding.validate_message(msg, base):
        explain('%s cannot be encoded in base %s (only A-Z)'
                % (msg, base))
        return None

    # Divide message in chunks if necessary.
    if decryption:
        chunks = split_cryptogram_in_blocks(msg, n, base)
    else:
        chunks = split_message_in_blocks(msg, n, base)

    encrypted_numbers = list()

    # Encode each chunk individually
    for chunk in chunks:
        chunk_number = encoding.get_as_number(chunk, base=base, cache=cache)

        explain(f'\nTransforming {chunk_number} into c = {chunk_number}^{key} (mod {n})')

        encrypted_numbers.append(modmath.fast_exp(chunk_number, key, n))

        explain(f'\n{chunk_number} gets converted to {encrypted_numbers[-1]}\n')

    return encrypted_numbers


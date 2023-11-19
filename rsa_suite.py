# Author: NachoGoro

import mathtools
import encodingtools
from blockmgr import (split_message_in_blocks, split_cryptogram_in_blocks,
                      assemble_cryptogram, assemble_message)
from io_explain import explain, explaining_method
import math


class RSA_Agent:
    """
    Class representing one side in an RSA communication.
    """

    def __init__(self, name, p=None, q=None, n=None, phi_n=None,
                 e=None, d=None):
        """
        Constructor.

        Not all parameters are necessary, some can be inferred from others. The
        class is flexible enough to adapt to the ones provided.

        name: name of the agent (for ease of identification in explanations)
        p: one of the two prime factors of n, along with q
        q: one of the two prime factors of n, along with p
        n: large number, product of p and q
        phi_n: result of applying the function phi of Euler to n ((p-1)*(q-1))
        e: public key of the agent
        d: private key of the agent
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
            self.d = mathtools.get_inverse(self.e, self.get_phi_n(), False)

        return self.d

    def get_public_key(self):
        """
        Returns the public key of the agent
        """
        if not self.e and self.d and self.get_phi_n():
            # Public key can be derived from private key and phi_n
            self.e = mathtools.get_inverse(self.d, self.get_phi_n())

        return self.e


@explaining_method
def encrypt(msg, sender, receiver, base=27):
    """
    Encrypts a message using RSA.

    msg: message to be encrypted.
    sender: RSA_Agent which will send the message. In RSA, it's irrevelant
            when it comes to encrypting.
    receiver: RSA_Agent which will receive the message being encrypted.
    base: number of symbols to be used in the alphabet. Currently supported
            26 (English) and 27 (Spanish)
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
        decrypt=False,
        base=base,
        cache=cached_conversions)

    explain('In order to get the cryptogram, we represent the blocks as strings')
    encrypted_blocks = [encodingtools.get_as_string(block, base)
                            for block in encrypted_numbers]

    return assemble_cryptogram(encrypted_blocks,
                               receiver.get_n(),
                               base,
                               cache=cached_conversions)


@explaining_method
def decrypt(msg, sender, receiver, base=27):
    """
    Decrypts a message using RSA.

    msg: message to be decrypted.
    sender: RSA_Agent which sent the message. In RSA, it's irrevelant
            when it comes to decrypting.
    receiver: RSA_Agent which received the encrypted message.
    base: number of symbols to be used in the alphabet. Currently supported
            26 (English) and 27 (Spanish)
    """
    cached_conversions = dict()
    # In order to decrypt a message we just need the private key and n of
    # the receiver
    if not receiver.get_private_key() or not receiver.get_n():
        explain('Private key or n of %s is unknown' % str(receiver.name))
        return None

    decrypted_numbers = _transform(msg=msg, key=receiver.get_private_key(),
                                      n=receiver.get_n(), cache=cached_conversions,
                                      base=base, decrypt=True)

    explain('In order to get the clear message, we represent the blocks as strings')
    decrypted_blocks = [encodingtools.get_as_string(block, base)
                        for block in decrypted_numbers]

    return assemble_message(decrypted_blocks,
                            receiver.get_n(),
                            base,
                            cache=cached_conversions)

@explaining_method
def sign(msg, sender, receiver, base=27, hash_fn=None):
    """
    Signs a message to be sent to an agent using RSA.

    The message will be signed by the sender and encrypted for the
    receiver.

    msg: message to be signed.
    sender: RSA_Agent which will send the message.
    receiver: RSA_Agent which will receive the signed message.
    base: number of symbols to be used in the alphabet. Currently supported
            26 (English) and 27 (Spanish)
    hash_fn: optional parameter. A hash function to apply to the message
             before signing it. It must be an explaining_method, and take
             two parameters (message to hash as a string and base to use)
             and return the hashed message as a number.
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
                                   n=sender.get_n(), base=base, decrypt=False)

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
    signature_blocks = [encodingtools.get_as_string(block, base)
                        for block in signed_numbers]

    return assemble_cryptogram(signature_blocks,
                               receiver.get_n(),
                               base,
                               cache=cached_conversions)

@explaining_method
def _transform(msg, key, n, base, decrypt=False, cache=None):
    """
    Private method. Applies a given key to a message, which can be used for
    encrypting, decrypting or signing.

    Returns the individual chunks of the message as integers, for the caller to
    assemble as they see fit.

    msg: message to be encrypted. It can be in string or numeric form.
    key: key to be used for encryption.
    n: modulo for the encryption operations.
    base: number of symbols to be used in the alphabet. Currently supported
            26 (English) and 27 (Spanish)
    decrypt: whether the method is being used for decrypting a message
    (necessary to determine the size of the chunks in which the message
    needs to be split).
    """
    if cache is None:
        cache = dict()

    if type(msg) is str and not encodingtools.validate_message(msg, base):
        explain('%s cannot be encoded in base %s (only A-Z)'
                % (msg, base))
        return None

    # Divide message in chunks if necessary.
    if decrypt:
        chunks = split_cryptogram_in_blocks(msg, n, base)
    else:
        chunks = split_message_in_blocks(msg, n, base)

    encrypted_numbers = list()

    # Encode each chunk individually
    for chunk in chunks:
        chunk_number = encodingtools.get_as_number(chunk, base=base, cache=cache)

        explain(f'\nTransforming {chunk_number} into c = {chunk_number}^{key} (mod {n})')

        encrypted_numbers.append(mathtools.quick_exp(chunk_number, key, n))

        explain(f'\n{chunk_number} gets converted to {encrypted_numbers[-1]}\n')

    return encrypted_numbers

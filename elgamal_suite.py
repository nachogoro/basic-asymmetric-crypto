# Author: NachoGoro

import mathtools
import encodingtools
from io_explain import explaining_method, explain
from random import randrange
from collections import namedtuple
from blockmgr import (split_message_in_blocks, split_cryptogram_in_blocks,
                      assemble_message, assemble_cryptogram,
                      assemble_signature)
from elgamal_types import Encrypted_Pair, Signed_Pair

class ElGamal_Agent:
    """
    Class representing one side in an ElGamal communication.
    """
    def __init__(self, name, private_key=None):
        """
        Constructor.

        name: name of the agent (for ease of identification in explanations)
        private_key: private key of the agent
        """
        self.name = name
        self.private_key = private_key


    def get_private_key(self):
        return self.private_key


    @explaining_method
    def get_public_key(self, generator, p):
        if not self.private_key:
            # Public key cannot be computed without a private key
            explain(
                'Cannot compute public key for %s without its private key'
                % self.name)
            return None

        explain(
            'Public key for %s is computed from its private key as: %d ^ %d (mod %d)'
            % (self.name, generator, self.private_key, p))

        public_key = mathtools.quick_exp(
            generator,
            self.private_key,
            p)

        explain(
            'Public key for %s with generator=%d and p=%d is %d'
            %(self.name, generator, p, public_key))

        return public_key


@explaining_method
def encrypt(msg, sender, receiver, p, generator, v=None, base=27):
    """
    Encrypts a message using ElGamal.

    msg: message to be encrypted.
    sender: ElGamal_Agent which will send the message. In ElGamal, he's
            irrevelant when it comes to encrypting.
    receiver: ElGamal_Agent which will receive the message being encrypted.
    p: prime number to use for this encryption (known by sender and
        receiver).
    generator: generator to use for this encryption (known by sender and
                receiver).
    v: arbitrary number to use for the encryption. If not specified, a
        random number will be selected.
    base: number of symbols to be used in the alphabet. Currently supported
            26 (English) and 27 (Spanish)
    """
    cached_conversions = dict()
    # In order to encrypt a message we just need the public key of the
    # receiver
    if not receiver.get_public_key(generator, p):
        explain('Public key of %s is unknown' % str(receiver.name))
        return None

    msg = msg.upper()

    if not encodingtools.validate_message(msg, base):
        explain('%s cannot be encoded in base %s (only A-Z)'
                % (msg, base))
        return None

    explain('\nIn ElGamal, the cryptogram is a pair (g^v mod p, m·B^v mod'
            ' p), where:\n'
            '\t- g is the generator\n'
            '\t- p is the shared prime\n'
            '\t- m is the message\n'
            '\t- v is the random number used for encryption\n'
            '\t- B is the receiver\'s public key\n')

    chunks = split_message_in_blocks(msg, p, base)

    encrypted_pairs = list()

    if len(chunks) > 1 and v:
        explain('All chunks will be encrypted with the same v (this is a security concern)')

    # Encode each chunk individually
    for chunk in chunks:
        v_for_block = v

        if not v_for_block:
            v_for_block = randrange(2, p)
            explain('v not set, selecting random number v = %d' % v_for_block)

        chunk_number = encodingtools.get_as_number(chunk,
                                                   base,
                                                   cache=cached_conversions)

        explain(f'\nEncrypting {chunk} as ('
                f'{generator}^{v_for_block} mod {p}, '
                f'{chunk_number}*{receiver.get_public_key(generator, p)}^{v_for_block} mod {p})')

        g_v=mathtools.quick_exp(generator, v_for_block, p)
        g_v_b = mathtools.quick_exp(receiver.get_public_key(generator, p),
                                    v_for_block,
                                    p)
        m_g_v_b = chunk_number * g_v_b % p
        explain(f'\n{chunk_number}*{g_v_b} mod {p} = {m_g_v_b}')

        encrypted_pairs.append(Encrypted_Pair(g_v=g_v, m_g_v_b=m_g_v_b))

        explain(f'\n{chunk} gets encrypted to ({g_v}, {m_g_v_b})\n')

    explain('To get the cryptogram, we must first express all blocks as strings')
    encrypted_pairs_str = []
    for pair in encrypted_pairs:
        as_str = Encrypted_Pair(encodingtools.get_as_string(pair.g_v, base, explain=False),
                                encodingtools.get_as_string(pair.m_g_v_b, base, explain=False))
        explain(f'{pair} in base {base} is {as_str}')
        encrypted_pairs_str.append(as_str)

    return assemble_cryptogram(encrypted_pairs_str, p, base, cache=cached_conversions)


@explaining_method
def decrypt(msg_pair, sender, receiver, p, generator, base=27):
    """
    Decrypts a message using ElGamal.

    msg_pair: message pair to be decrypted.
    sender: ElGamal_Agent which sent the message. In ElGamal, he's
            irrevelant when it comes to decrypting.
    receiver: ElGamal_Agent which received the message being encrypted.
    p: prime number to use for this encryption (known by sender and
       receiver).
    generator: generator to use for this encryption (known by sender and
               receiver).
    base: number of symbols to be used in the alphabet. Currently supported
          26 (English) and 27 (Spanish)
    """

    cached_conversions = dict()

    # In order to decrypt a message we just need the private key of the
    # receiver
    if not receiver.get_private_key():
        explain('Private key of %s is unknown' % str(receiver.name))
        return None

    msg_pair = Encrypted_Pair(g_v=msg_pair.g_v.upper(),
                              m_g_v_b=msg_pair.m_g_v_b.upper())

    if not (encodingtools.validate_message(msg_pair.g_v, base)
            and encodingtools.validate_message(msg_pair.m_g_v_b, base)):
        explain('(%s, %s) cannot be encoded in base %s (only A-Z)'
                % (msg_pair.g_v, msg_pair.m_g_v_b, base))
        return None

    chunks = split_cryptogram_in_blocks(msg_pair, p, base)

    decrypted_chunks = list()

    for encrypted_pair in chunks:
        gv = encrypted_pair.g_v
        mgvb = encrypted_pair.m_g_v_b
        explain(f'\nDecrypting pair ({gv}, {mgvb})')
        explain(f'\nWe need to encode g^v ({gv}) and m*(g^b)^v ({mgvb}) as numbers')

        gv_as_number = encodingtools.get_as_number(gv,
                                                   base,
                                                   cache=cached_conversions)

        mgvb_as_number = encodingtools.get_as_number(mgvb,
                                                     base,
                                                     cache=cached_conversions)

        explain('\nWe need to compute (g^v)^b mod p '
                f'({gv_as_number}^{receiver.get_private_key()} mod {p})')

        gvb_as_number = mathtools.quick_exp(
            gv_as_number,
            receiver.get_private_key(),
            p)

        explain(f'\nWe now need to find its multiplicative inverse in p={p}')

        gvb_inverse = mathtools.get_inverse(gvb_as_number, p)

        explain('\nWe can finally recover the message by: '
                'm = inverse((g^v)^b) * m*(g^v)^b (mod p) ---> '
                'm = %d * %d (mod %d)'
                % (gvb_inverse, mgvb_as_number, p))

        result = (gvb_inverse * mgvb_as_number) % p

        explain('\nThe recovered chunk is %d (mod %d)' % (result, p))
        explain('\nWe now encode it in base %d' % base)

        decrypted_chunk = encodingtools.get_as_string(result,
                                                      base,
                                                      cache=cached_conversions)

        decrypted_chunks.append(decrypted_chunk)
        explain()

    return assemble_message(decrypted_chunks,
                            p,
                            base,
                            cache=cached_conversions)


@explaining_method
def sign(msg, sender, receiver, p, generator, h=None, base=27, hash_fn=None):
    """
    Signs a message using ElGamal.

    msg: message to be signed.
    sender: ElGamal_Agent which will send the message.
    receiver: ElGamal_Agent which will receive the message being encrypted.
    p: prime number to use for this encryption (known by sender and
        receiver).
    generator: generator to use for this signing (known by sender and
                receiver).
    h: arbitrary co-prime number with (p-1) to be used for signing. If not
        specified, a random number will be selected.
    v: arbitrary number to use for the encryption. If not specified, a
        random number will be selected.
    base: number of symbols to be used in the alphabet. Currently supported
            26 (English) and 27 (Spanish)
    hash_fn: optional parameter. A hash function to apply to the message
             before signing it. It must be an explaining_method, and take
             two parameters (message to hash as a string and base to use)
             and return the hashed message as a number.
    """

    cached_conversions = dict()

    # In order to sign a message with ElGamal we just need the private key
    # of the sender
    if not sender.get_private_key():
        explain('Private key of %s is unknown' % str(sender.name))
        return None

    msg = msg.upper()

    if not encodingtools.validate_message(msg, base):
        explain('%s cannot be encoded in base %s (only A-Z)'
                % (msg, base))
        return None

    msg_to_sign = msg

    if hash_fn:
        # A hash has been specified
        explain('First of all, we need to hash the message')

        msg_to_sign = hash_fn(msg, base)

        explain(f'hash({msg}) = {msg_to_sign}')
    else:
        explain('No hash function has been specified, so we will sign the '
                'message as-is')

    # Divide message in chunks if necessary
    chunks = split_message_in_blocks(msg_to_sign, p, base)

    if h and len(chunks) > 1:
        explain(f'The same h={h} will be used to sign all blocks')

    signed_blocks = list()

    # Sign each chunk individually
    for chunk in chunks:
        explain(f'Let\'s sign block {chunk}')
        explain(f'We must solve the equation m = a*r + h*s (mod p-1)')

        h_for_block = h
        if not h_for_block:
            h_for_block = mathtools.get_coprime_in_range(p-1)
            explain('h not set, selecting random co-prime of (p-1) h ={h}')

        chunk_number = encodingtools.get_as_number(chunk,
                                                   base=base,
                                                   cache=cached_conversions)

        explain(f'First, compute r = g^h (mod p) ---> r = {generator}^{h} (mod {p})')

        r = mathtools.quick_exp(generator, h, p)

        explain(f'\nResolving the equation for m = {chunk} ---> '
                f'{chunk_number} = {sender.get_private_key()}*{r} + {h}*s (mod {p-1})')

        explain(f'\nFor this we need the inverse of {h} in {p-1}')

        chunk_signature = (
            ((chunk_number
                - (sender.get_private_key() * r))
                * mathtools.get_inverse(h, p-1))
            % (p-1))

        explain(f's = (m - (a*r)) * h^(-1) (mod p-1) ---> s = {chunk_signature}')

        explain('We now encode both r and s as strings to get a signature block')
        signature_block = Signed_Pair(r=encodingtools.get_as_string(r,
                                                                    base,
                                                                    cache=cached_conversions),
                                      s=encodingtools.get_as_string(chunk_signature,
                                                                    base,
                                                                    cache=cached_conversions))
        explain(f'Signature block: {signature_block}')
        signed_blocks.append(signature_block)

    return assemble_signature(signed_blocks, p, base)

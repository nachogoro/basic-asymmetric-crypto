# Author: NachoGoro

import mathtools
import encodingtools
from random import randrange
from collections import namedtuple

class ElGamal_Agent:
    """
    Class representing one side in an ElGamal communication.
    """
    def __init__(self, name, private_key=None):
        """
        Constructor.

        name: name of the agent (for ease of identification in debug messages)
        private_key: private key of the agent
        """
        self.name = name
        self.private_key = private_key


    def get_private_key(self):
        return self.private_key


    def get_public_key(self, generator, p, debug=False):
        if not self.private_key:
            # Public key cannot be computed without a private key
            if debug:
                print(
                    'Cannot compute public key for %s without its private key'
                    % self.name)
            return None

        if debug:
            print(
                'Public key for %s is computed from its private key as: %d ^ %d (mod %d)'
                % (self.name, generator, self.private_key, p))

        public_key = mathtools.quick_exp(
            generator,
            self.private_key,
            p,
            debug=debug)

        if debug:
            print(
                'Public key for %s with generator=%d and p=%d is %d'
                %(self.name, generator, p, public_key))

        return public_key


"""
ElGamal encrypts one message into as pair of strings.

This class represents the result of encrypting one message.
"""
Encrypted_Pair = namedtuple(
    'Encrypted_Pair',
    ['g_v', 'm_g_v_b'])

"""
ElGamal signs one message into as pair of strings.

This class represents the result of signing one message.
"""
Signed_Pair = namedtuple(
    'Signed_Pair',
    ['r', 's'])


class ElGamal:
    """
    Container class for the main operations to be performed by ElGamal
    """

    @staticmethod
    def encrypt(msg, sender, receiver, p, generator, v=None, base=27, debug=False):
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
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        """
        # In order to encrypt a message we just need the public key of the
        # receiver
        if not receiver.get_public_key(generator, p, debug=debug):
            if debug:
                print('Public key of %s is unknown' % str(receiver.name))
            return None

        msg = msg.upper()

        if not encodingtools.validate_message(msg, base):
            if debug:
                print('%s cannot be encoded in base %s (only A-Z)'
                      % (msg, base))
            return None

        if debug:
            print('\nIn ElGamal, the cryptogram is a pair (g^v mod p, m·B^v mod'
                  ' p), where g is the generator, p is the prime, m is the'
                  ' message, v is the random number used for encryption and B'
                  ' is the receiver\'s public key')

        block_size = encodingtools.compute_block_size(p, base)
        if type(msg) is str:
            must_split = len(msg) > block_size
        else:
            must_split = msg >= p

        if must_split:
            chunks = encodingtools.get_msg_chunks(msg, base, p,
                                                  round_down=True)
        else:
            chunks = [msg]

        if debug:
            if type(msg) is str:
                print(
                    f'Since the block size is floor(log{base}({p})) = {block_size} characters, '
                    f'and our message is {len(msg)} characters long, ', end='')
            else:
                print(
                    f'Since p={p} and the the message is {msg_number}, ', end='')

            if not must_split:
                print('there is no need to split the message')
            else:
                print(
                    f'the message has to be split in chunks of at max floor(log{base}({p})) = {block_size} characters')

            if must_split and type(msg) is int:
                # We need to split a message which was originally a number. For that, we will turn it into a string
                # first. Do the conversion to display it (no need to store the result)
                encodingtools.get_as_string(msg_number, base, cache=cached_conversions, debug=True)

            if must_split:
                print(f'The chunks are: {chunks}\n')

        encrypted_pairs = list()

        if debug and len(chunks) > 1 and v:
            print('All chunks will be encrypted with the same v (this is a security concern)')

        # Encode each chunk individually
        for chunk in chunks:
            v_for_block = v

            if not v_for_block:
                v_for_block = randrange(2, p)
                if debug:
                    print('v not set, selecting random number v = %d' % v_for_block)

            chunk_number = encodingtools.get_as_number(
                chunk, base=base, debug=debug)

            if debug:
                print(f'\nEncrypting {chunk} as ('
                      f'{generator}^{v_for_block} mod {p}, '
                      f'{chunk_number}*{receiver.get_public_key(generator, p)}^{v_for_block} mod {p})')

            g_v=mathtools.quick_exp(generator, v_for_block, p, debug=debug)
            g_v_b = mathtools.quick_exp(receiver.get_public_key(generator, p),
                                        v_for_block,
                                        p,
                                        debug=debug)
            m_g_v_b = chunk_number * g_v_b % p
            if debug:
                print(f'\n{chunk_number}*{g_v_b} mod {p} = {m_g_v_b}')


            encrypted_pairs.append(Encrypted_Pair(g_v=g_v, m_g_v_b=m_g_v_b))

            if debug:
                print(f'\n{chunk} gets encrypted to ({g_v}, {m_g_v_b})\n')

        if len(encrypted_pairs) == 1:
            if debug:
                print('\nSince we didn\'t have to split the message, '
                      'the result is simply '
                      f'({encrypted_pairs[0].g_v}, {encrypted_pairs[0].m_g_v_b}) '
                      f'as strings in base {base}')

            result = Encrypted_Pair(
                g_v=encodingtools.get_as_string(
                    encrypted_pairs[0].g_v,
                    base,
                    debug=debug),
                m_g_v_b=encodingtools.get_as_string(
                    encrypted_pairs[0].m_g_v_b,
                    base,
                    debug=debug))


            if debug:
                print('\nThe encrypted message is: (%s, %s)'
                      % (result.g_v, result.m_g_v_b))
            return result

        # More than one chunk, they need to be padded
        if debug:
            print('\nFinally, we assemble all the encrypted chunks, '
                  'padding each one with A (0) up to %d characters\n'
                  % (len(chunks[0]) + 1))

        result = Encrypted_Pair(g_v='', m_g_v_b='')

        for pair in encrypted_pairs:
            pair_as_string = Encrypted_Pair(
                g_v=encodingtools.get_as_string(
                    pair.g_v,
                    base,
                    debug=debug),
                m_g_v_b=encodingtools.get_as_string(
                    pair.m_g_v_b,
                    base,
                    debug=debug))

            # Pad with 'A' until one character more than the plan text chunk
            padded = Encrypted_Pair(
                g_v=pair_as_string.g_v.rjust(len(chunks[0]) + 1, 'A'),
                m_g_v_b=pair_as_string.m_g_v_b.rjust(len(chunks[0]) + 1, 'A'))

            if debug:
                print('\n(%s, %s) is (%s, %s) after padding\n'
                      % (pair_as_string.g_v, pair_as_string.m_g_v_b,
                         padded.g_v, padded.m_g_v_b))

            result = Encrypted_Pair(
                g_v=result.g_v + padded.g_v,
                m_g_v_b=result.m_g_v_b + padded.m_g_v_b)

        if debug:
            print('\nThe final result after assembling all blocks is: (%s, %s)'
                  %(result.g_v, result.m_g_v_b))

        return result


    @staticmethod
    def decrypt(msg_pair, sender, receiver, p, generator,
                base=27, debug=False):
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
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        """
        # In order to decrypt a message we just need the private key of the
        # receiver
        if not receiver.get_private_key():
            if debug:
                print('Private key of %s is unknown' % str(receiver.name))
            return None

        msg_pair = Encrypted_Pair(g_v=msg_pair.g_v.upper(),
                                  m_g_v_b=msg_pair.m_g_v_b.upper())

        if not (encodingtools.validate_message(msg_pair.g_v, base)
                and encodingtools.validate_message(msg_pair.m_g_v_b, base)):
            if debug:
                print('(%s, %s) cannot be encoded in base %s (only A-Z)'
                      % (msg_pair.g_v, msg_pair.m_g_v_b, base))
            return None

        if debug:
            # Continue here
            block_size = floor(log())
            print(f'Decrypting pair ({msg_pair.g_v}, {msg_pair.m_g_v_b})')
            print('Block size for the shared prime is floor(log27({p})) =  ')

        # Divide message pair in chunks if necessary.
        gv_chunks = encodingtools.get_msg_chunks(
            msg_pair.g_v,
            base,
            p,
            round_down=False)

        mgvb_chunks = encodingtools.get_msg_chunks(
            msg_pair.m_g_v_b,
            base,
            p,
            round_down=False)

        if debug:
            if len(gv_chunks) == 1:
                print('\nNo need to split the message for decrypting\n')
            else:
                print('\nThe message will be split in chunks of %d characters\n'
                      % len(gv_chunks[0]))

        decrypted_chunks = list()

        for i in range(0, len(gv_chunks)):
            gv_chunk = gv_chunks[i]
            mgvb_chunk = mgvb_chunks[i]

            if debug:
                print('\nDecrypting pair (%s, %s)' % (gv_chunk, mgvb_chunk))
                print('\nWe need to encode g^v (%s) and m*(g^b)^v (%s) as a number'
                      % (gv_chunk, mgvb_chunk))

            gv_as_number = encodingtools.get_as_number(gv_chunk, base, debug=debug)
            mgvb_as_number = encodingtools.get_as_number(mgvb_chunk, base, debug=debug)

            if debug:
                print('\nWe need to compute (g^v)^b mod p (%d^%d mod %d)'
                      % (gv_as_number, receiver.get_private_key(), p))

            gvb_as_number = mathtools.quick_exp(
                gv_as_number,
                receiver.get_private_key(),
                p,
                debug)

            if debug:
                print('\nWe now need to find its multiplicative inverse in p (%d)'
                      % p)

            gvb_inverse = mathtools.get_inverse(gvb_as_number, p, debug)

            if debug:
                print('\nWe can finally recover the message by: '
                      'm = inverse((g^v)^b) * m*(g^v)^b (mod p) ---> '
                      'm = %d * %d (mod %d)'
                      % (gvb_inverse, mgvb_as_number, p))

            result = (gvb_inverse * mgvb_as_number) % p

            if debug:
                print('\nThe recovered chunk is %d (mod %d)' % (result, p))
                print('\nWe simply need to encode it in base %d' % base)

            decrypted_chunks.append(
                encodingtools.get_as_string(result, base, debug=debug))

            print()

        decrypted_msg = ''.join(decrypted_chunks)

        if len(gv_chunks) > 1:
            print('\nFinally, we just assemble all messages to retrieve the '
                  'original message: %s'
                  % decrypted_msg)
        else:
            print('\nThe recovered message is therefore: %s'
                  % decrypted_msg)

        return decrypted_msg


    @staticmethod
    def sign(msg, sender, receiver, p, generator,
             h=None, base=27, hash_fn=None, debug=False):
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
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        """

        # In order to sign a message with ElGamal we just need the private key
        # of the sender
        if not sender.get_private_key():
            if debug:
                print('Private key of %s is unknown' % str(sender.name))
            return None

        msg = msg.upper()

        if not encodingtools.validate_message(msg, base):
            if debug:
                print('%s cannot be encoded in base %s (only A-Z)'
                      % (msg, base))
            return None

        msg_to_sign = msg

        if hash_fn:
            # A hash has been specified
            if debug:
                print('First of all, we need to hash the message')

            msg_to_sign = hash_fn(msg, base, debug)

            if debug:
                print('hash(%s) = %s' % (msg, msg_to_sign))

            if not encodingtools.validate_message(msg_to_sign, base):
                if debug:
                    print('%s cannot be encoded in base %s (only A-Z)'
                        % (msg_to_sign, base))
                return None

        elif debug:
            print('No hash function has been specified, '
                  'so we will sign the message as-is')

        if not h:
            h = mathtools.get_coprime_in_range(p - 1)
            if debug:
                print('h not set, selecting random co-prime of (p-1) h = %d'
                      % h)

        if debug:
            print('First, compute r = g^h (mod p) ---> r = %d^%d (mod %d)'
                  % (generator, h, p))

        r = mathtools.quick_exp(generator, h, p, debug)

        if debug:
            print('\nNow we encode r as a string:')

        r_as_string = encodingtools.get_as_string(r, base, debug=debug)

        # Divide message in chunks if necessary
        chunks = encodingtools.get_msg_chunks(msg_to_sign, base, p,
                                              round_down=True)

        if debug:
            if len(chunks) == 1:
                print('\nNo need to split the message for signing')
                print('\nNow resolve: m = a*r + h*s (mod p-1)')
            else:
                print('\nThe message will be split in chunks of %d characters'
                      % len(chunks[0]))
                print('\nNow resolve for each chunk: m = a*r + h*s (mod p-1)')

        signed_chunks = list()

        # Sign each chunk individually
        for chunk in chunks:
            chunk_number = encodingtools.get_as_number(
                chunk, base=base, debug=debug)

            if debug:
                print('\nResolving the equation for m = %s ---> %d = %d*%d + %d*s (mod %d)'
                      % (chunk,
                         chunk_number,
                         sender.get_private_key(),
                         r,
                         h,
                         p-1))
                print('\nFor this we need the inverse of h (%d) in (p-1) (%d)'
                      % (h, p-1))

            chunk_signature = (
                ((chunk_number
                 - (sender.get_private_key() * r))
                 * mathtools.get_inverse(h, p-1, debug))
                % (p-1))

            print('s = (m - (a*r)) * h^(-1) (mod p-1) ---> s = %d' % chunk_signature)

            signed_chunks.append(chunk_signature)

        if len(signed_chunks) == 1:
            if debug:
                print('\nSince we didn\'t have to split the message, '
                      'the signed message is simply (r, s) = (%d, %d) as '
                      'strings in base %d'
                    % (r,
                       signed_chunks[0],
                       base))

            result = Signed_Pair(
                r=r_as_string,
                s=encodingtools.get_as_string(
                    signed_chunks[0],
                    base,
                    debug=debug))

            if debug:
                print('\nThe signed message is: (%s, %s)'
                      % (result.r, result.s))

        else:
            # More than one chunk, they need to be padded if we are signing
            if debug:
                print('\nFinally, we assemble all the signed chunks, '
                    'padding each one with A (0) up to %d characters\n'
                    % (len(chunks[0]) + 1))

            assembled_signature = ''

            for signed_chunk in signed_chunks:
                chunk_as_string = encodingtools.get_as_string(
                    signed_chunk,
                    base,
                    debug=debug)

                # Pad with 'A' until one character more than the plan text chunk
                padded = chunk_as_string.rjust(len(chunks[0]) + 1, 'A')

                if debug:
                    print('\n%s is %s after padding\n'
                        % (chunk_as_string, padded))

                    assembled_signature += padded

            result = Signed_Pair(
                r=r_as_string,
                s=assembled_signature)

            if debug:
                print('\nThe result after assembling all blocks is: (r, s) = (%s, %s)'
                      %(result.r, result.s))

        return result

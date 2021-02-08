# Author: NachoGoro

import mathtools
import encodingtools
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

        name: name of the agent (for ease of identification in debug messages)
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

        if p and q and phi_n and (phi_n != (p-1)*(q-1)):
            raise Exception(
                'Inconsistent values phi_n, p and q ({} != ({}-1)*({}-1))'
                .format(phi_n, p, q))

        tmp_phi_n = None

        if (p and q):
            tmp_phi_n = (p-1)*(q-1)
        elif phi_n:
            tmp_phi_n = phi_n

        if tmp_phi_n:
            if e and d and ((e*d % tmp_phi_n) != 1):
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
            self.phi_n = (self.p - 1)*(self.q - 1)

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

class RSA:
    """
    Container class for the main operations to be performed by RSA
    """

    @staticmethod
    def encrypt(msg, sender, receiver, base=27, debug=False):
        """
        Encrypts a message using RSA.

        msg: message to be encrypted.
        sender: RSA_Agent which will send the message. In RSA, he's irrevelant
                when it comes to encrypting.
        receiver: RSA_Agent which will receive the message being encrypted.
        base: number of symbols to be used in the alphabet. Currently supported
              26 (English) and 27 (Spanish)
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        """
        # In order to encrypt a message we just need the public key and n of the
        # receiver
        if not receiver.get_public_key() or not receiver.get_n():
            if debug:
                print('Public key or n of %s is unknown' % str(receiver.name))
            return None

        encrypted_numbers = RSA._encrypt(
            msg=msg,
            key=receiver.get_public_key(),
            n=receiver.get_n(),
            base=base,
            debug=debug)

        if len(encrypted_numbers) == 1:
            if debug:
                print('\nSince we didn\'t have to split the message, '
                    'the result is simply %d as a string in base %d'
                    % (encrypted_numbers[0], base))

            result = encodingtools.get_as_string(
                encrypted_numbers[0],
                base,
                debug=debug)

            if debug:
                print('\nThe resulting message is: %s' % result)
            return result

        result = RSA._assemble(encrypted_numbers,
                  receiver.get_n(),
                  base,
                  debug=debug)

        return result


    @staticmethod
    def decrypt(msg, sender, receiver, base=27, debug=False):
        """
        Decrypts a message using RSA.

        msg: message to be decrypted.
        sender: RSA_Agent which sent the message. In RSA, it's irrevelant
                when it comes to decrypting.
        receiver: RSA_Agent which received the encrypted message.
        base: number of symbols to be used in the alphabet. Currently supported
              26 (English) and 27 (Spanish)
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        """
        # In order to decrypt a message we just need the private key and n of
        # the receiver
        if not receiver.get_private_key() or not receiver.get_n():
            if debug:
                print('Private key or n of %s is unknown' % str(receiver.name))
            return None

        decrypted_chunks = RSA._encrypt(msg=msg, key=receiver.get_private_key(),
                            n=receiver.get_n(), base=base, decrypt=True,
                            debug=debug)

        if len(decrypted_chunks) == 1:
            if debug:
                print('\nSince we didn\'t have to split the message, '
                    'the result is simply %d as a string in base %d'
                    % (decrypted_chunks[0], base))

            result = encodingtools.get_as_string(
                decrypted_chunks[0],
                base,
                debug=debug)

            if debug:
                print('\nThe resulting message is: %s' % result)
            return result

        result = RSA._assemble(decrypted_chunks,
                  None,
                  base,
                  debug=debug)

        if debug:
            print('\nThe resulting message is: %s' % result)
        return result


    @staticmethod
    def sign(msg, sender, receiver, base=27, hash_fn=None,
             encrypt_for_receiver=True, debug=False):
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
                 before signing it. It must take three parameters (message to
                 hash as a string, base to use and the debug flag) and return
                 the hashed message as a string.
        encrypt_for_receiver: Whether the signature should be encrypted with
                              the receiver's public key (True by default, as it
                              is a weakness in RSA not to do it).
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        """
        # In order to sign a message we need the public key and n of the
        # receiver and the private key and n of the sender
        if not receiver.get_public_key() or not receiver.get_n():
            if debug:
                print('Public key or n of %s is unknown' % str(receiver.name))
            return None

        if not sender.get_private_key() or not sender.get_n():
            if debug:
                print('Private key or n of %s is unknown' % str(sender.name))
            return None

        # We first encrypt with the private key of the sender and the result
        # with the public key of the receiver

        msg = msg.upper()

        msg_to_sign = msg

        if hash_fn:
            # A hash has been specified
            if debug:
                print('First of all, we need to hash the message')

            msg_to_sign = hash_fn(msg, base, debug)

            if debug:
                print('hash(%s) = %s' % (msg, msg_to_sign))
        elif debug:
            print('No hash function has been specified, '
                  'so we will sign the message as-is')

        if debug:
            print('\nFirst step is to compute the rubric of the message (i.e. '
                  'encrypting the message with the sender\'s private key)')

        rubric_chunks = RSA._encrypt(msg=msg_to_sign, key=sender.get_private_key(),
                              n=sender.get_n(), base=base, debug=debug)

        if debug:
            print('\nWe obtain the following chunks for the rubric: '
                  + str(rubric_chunks))



        if not encrypt_for_receiver:
            if len(rubric_chunks) == 1:
                return encodingtools.get_as_string(
                    rubric_chunks[0],
                    base,
                    debug=debug)

            return RSA._assemble(rubric_chunks,
                                 sender.get_n(),
                                 base,
                                 debug=debug)

        if debug:
            print(
                '\nWe now need to encrypt each chunk of the rubric '
                'individually with the receiver\'s public key to avoid attacks.')

        signed_chunks = list()

        for chunk in rubric_chunks:
            if debug:
                print('\nEncoding chunk %d (%s):'
                      % (chunk,
                         encodingtools.get_as_string(chunk, base, False)))

            signed_chunks.append(
                RSA._assemble(
                    RSA._encrypt(msg=encodingtools.get_as_string(chunk,
                                                                 base,
                                                                 False),
                                 key=receiver.get_public_key(),
                                 n=receiver.get_n(),
                                 base=base,
                                 debug=debug),
                    receiver.get_n(),
                    base,
                    debug=debug))

        if len(signed_chunks) == 1:
            signature = '(%s, %s)' % (msg,
                                      signed_chunks[0])

            if debug:
                print('\nSince we didn\'t need to split the message, '
                      'the signature is simply %s' % signature)
            return signature

        if debug:
            print('\nFinally we simply assemble the signed chunks to obtain '
                  'the signature.')

        signature = (
            '(%s, %s)'
            % (msg,
               RSA._assemble([encodingtools.get_as_number(e, base, debug)
                              for e in signed_chunks],
                             receiver.get_n(),
                             base,
                             debug)))

        if debug:
            print('\nThe final result is then: %s' % signature)

        return signature


    @staticmethod
    def _encrypt(msg, key, n, base, debug, decrypt=False):
        """
        Private method. Applies a given key to a message, which can be used for
        encrypting, decrypting or signing.

        Returns the individual chunks of the messages, for the caller to
        assemble as they see fit.

        msg: message to be encrypted. It can be in string or numeric form.
        key: key to be used for encryption.
        n: modulo for the encryption operations.
        base: number of symbols to be used in the alphabet. Currently supported
              26 (English) and 27 (Spanish)
        debug: if set to True, the method will log all the steps used to reach
               the solution.
        decrypt: whether the method is being used for decrypting a message
        (necessary to determine the size of the chunks in which the message
        needs to be split).
        """
        if type(msg) is str:
            msg_string = msg.upper()
            msg_number = encodingtools.get_as_number(
                msg_string,
                base,
                debug=debug)
        else:
            # msg is an int
            msg_number = msg
            msg_string = encodingtools.get_as_string(
                msg_number,
                base,
                debug=debug)

        if not encodingtools.validate_message(msg_string, base):
            if debug:
                print('%s cannot be encoded in base %s (only A-Z)'
                      % (msg, base))
            return None

        # Divide message in chunks if necessary
        if msg_number < n:
            chunks = [msg_string]
        else:
            chunks = encodingtools.get_msg_chunks(msg_string, base, n,
                                                  round_down=(not decrypt))

        if debug:
            if len(chunks) == 1:
                print('Since %d is smaller than %d, '
                      'there is no need to split the message'
                      % (msg_number, n))
            else:
                print('Since %d is not smaller than %d, the message will '
                      'be split in chunks of %d characters'
                      % (msg_number, n, len(chunks[0])))

        encrypted_numbers = list()

        # Encode each chunk individually
        for chunk in chunks:
            chunk_number = encodingtools.get_as_number(
                chunk, base=base, debug=debug)

            if debug:
                print('\nTransforming %s into c = %d^%d (mod %d)'
                      % (chunk,
                         chunk_number,
                         key,
                         n))

            encrypted_numbers.append(
                mathtools.quick_exp(chunk_number,
                                    key,
                                    n,
                                    debug=debug))

            if debug:
                print('\n%s gets converted to %d (\'%s\')'
                      % (chunk,
                         encrypted_numbers[-1],
                         encodingtools.get_as_string(encrypted_numbers[-1],
                                                     base,
                                                     False)))

        return encrypted_numbers


    @staticmethod
    def _assemble(chunks_as_numbers, n, base, debug):
        """
        Private method. Assembles a series of numeric chunks, which are being
        encrypted/decrypted for the specified modulo n.

        It pads the chunks with 'A' to the left as necessary.

        If no n is specified, it is assumed it's a decryption operation and no
        padding is necessary.
        """

        if len(chunks_as_numbers) == 1:
            return encodingtools.get_as_string(
                chunks_as_numbers[0],
                base,
                False)

        # If no n is provided, we are decrypting and no padding is necessary.
        # If an n is provided, we are encrypting/signing and need to pad to one
        # letter more than the plain text chunk
        if n:
            padded_length = int(math.log(n, base)) + 1
        else:
            padded_length = None

        if debug:
            if not padded_length:
                print('\nFinally, we assemble all the chunks\n')
            else:
                print('\nFinally, we assemble all the chunks, '
                    'padding each one with A (0) up to %d characters\n'
                    % padded_length)

        result = ''
        for number in chunks_as_numbers:
            number_as_string = encodingtools.get_as_string(
                number,
                base,
                debug=debug)

            # Pad with 'A' until one character more than the plan text chunk
            if padded_length:
                padded = number_as_string.rjust(padded_length, 'A')

                if debug:
                    print('\n%s is %s after padding\n'  % (number_as_string, padded))

                result += padded
            else:
                result += number_as_string

        if debug:
            print('\nThe final result after assembling all blocks is: %s'
                  % result)

        return result


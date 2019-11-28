import tools
import encodingtools

class RSA_Agent:
    def __init__(self, name, p=None, q=None, n=None, phi_n=None,
                 e=None, d=None):
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
        if not self.n and self.p and self.q:
            self.n = self.p * self.q

        return self.n


    def get_phi_n(self):
        if not self.phi_n and self.p and self.q:
            self.phi_n = (self.p - 1)*(self.q - 1)

        return self.phi_n


    def get_private_key(self):
        if not self.d and self.e and self.get_phi_n():
            # Private key can be derived from public key and phi_n
            self.d = tools.get_inverse(self.e, self.get_phi_n())

        return self.d

    def get_public_key(self):
        if not self.e and self.d and self.get_phi_n():
            # Public key can be derived from private key and phi_n
            self.e = tools.get_inverse(self.d, self.get_phi_n())

        return self.e

class RSA:
    @staticmethod
    def encrypt(msg, sender, receiver, base=27, debug=False):
        # In order to send a message we just need the public key and n of the
        # receiver
        if not receiver.get_public_key() or not receiver.get_n():
            if debug:
                print('Public key or n of %s is unknown' % str(receiver.name))
            return None

        return RSA._encrypt(msg=msg, key=receiver.get_public_key(),
                            n=receiver.get_n(), base=base, debug=debug)



    @staticmethod
    def sign(msg, sender, receiver, base=27, hash_fn=None, debug=False):
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

        # We first encrypt with thea private key of the sender and the result
        # with the public key of the receiver

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
            print('First step is to compute the rubric of the message (i.e. '
                  'encrypting the message with the sender\'s private key)')

        rubric = RSA._encrypt(msg=msg_to_sign, key=sender.get_private_key(),
                              n=sender.get_n(), base=base, debug=debug)

        if debug:
            print('Finally, we need to encrypt the rubric '
                  'with the receiver\'s public key')

        signature = RSA._encrypt(msg=rubric, key=receiver.get_public_key(),
                                 n=receiver.get_n(), base=base, debug=debug)

        if debug:
            print('The final result is then: %s' % signature)


    @staticmethod
    def _encrypt(msg, key, n, base, debug):
        if not encodingtools.validate_message(msg, base):
            if debug:
                print('%s cannot be encoded in base %s (only A-Z)'
                      % (msg, base))
            return None

        msg = msg.upper()

        # Divide message in chunks if necessary
        chunks = encodingtools.get_msg_chunks(msg, base, n)

        if debug:
            if len(chunks) == 1:
                print('No need to split the message for encrypting')
            else:
                print('The message will be split in chunks of %d characters'
                      % len(chunks[0]))

        encrypted_numbers = list()

        # Encode each chunk individually
        for chunk in chunks:
            chunk_number = encodingtools.get_as_number(
                chunk, base=base, debug=debug)

            if debug:
                print('Encrypting %s as c = %d^%d (mod %d)'
                      % (chunk,
                         chunk_number,
                         key,
                         n))

            encrypted_numbers.append(
                tools.quick_exp(chunk_number,
                                key,
                                n,
                                debug=debug))

            if debug:
                print('%s gets encrypted to %d'
                      % (chunk,
                         encrypted_numbers[-1]))

        if len(encrypted_numbers) == 1:
            if debug:
                print('Since we didn\'t have to split the message, '
                    'the result is simply %d as a string in base %d'
                    % (encrypted_numbers[0], base))

            result = encodingtools.get_as_string(
                encrypted_numbers[0],
                base,
                debug=debug)

            if debug:
                print('The encrypted message is: %s' % result)
            return result

        # More than one chunk, they need to be padded
        if debug:
            print('Finally, we assemble all the encrypted chunks, '
                  'padding each one with A (0) up to %d characters'
                  % (len(chunks[0]) + 1))

        result = ''
        for number in encrypted_numbers:
            number_as_string = encodingtools.get_as_string(
                number,
                base,
                debug=debug)

            # Pad with 'A' until one character more than the plan text chunk
            padded = number_as_string.rjust(len(chunks[0]) + 1, 'A')

            if debug:
                print('%s is %s after padding'  % (number_as_string, padded))

            result += padded

        if debug:
            print('The final result after assembling all padded blocks is: %s'
                  % result)
        return result


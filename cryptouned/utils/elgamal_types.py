from collections import namedtuple

"""
A namedtuple representing the result of an ElGamal encryption.

This namedtuple consists of two elements:
g_v: The first part of the encrypted message.
m_g_v_b: The second part of the encrypted message.

These two elements together represent the encryption of a single message using ElGamal encryption.
"""
_Encrypted_Pair = namedtuple(
    'EncryptedPair',
    ['g_v', 'm_g_v_b'])


class EncryptedPair(_Encrypted_Pair):
    """
    Class representing an ElGamal encrypted message pair.

    Extends the _Encrypted_Pair namedtuple with custom string representation.
    The class holds the result of encrypting one message using ElGamal encryption,
    encapsulated as a pair of strings.

    Methods:
    __str__: Return a string representation of the encrypted message pair.
    """

    def __str__(self):
        return f'({self.g_v}, {self.m_g_v_b})'



"""
A namedtuple representing the result of an ElGamal signature.

This namedtuple consists of two elements:
r: The first part of the signature.
s: The second part of the signature.

These two elements together represent the signature of a message using ElGamal signature scheme.
"""
_Signed_Pair = namedtuple(
    'SignedPair',
    ['r', 's'])


class SignedPair(_Signed_Pair):
    """
    Class representing an ElGamal signed message pair.

    Extends the _Signed_Pair namedtuple with custom string representation.
    The class holds the result of signing one message using ElGamal signature,
    encapsulated as a pair of strings.

    Methods:
    __str__: Return a string representation of the signed message pair.
    """

    def __str__(self):
        return f'(r={self.r}, s={self.s})'


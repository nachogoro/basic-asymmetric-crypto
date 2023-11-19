from collections import namedtuple

"""
ElGamal encrypts one message into as pair of strings.

This class represents the result of encrypting one message.
"""
_Encrypted_Pair = namedtuple(
    'Encrypted_Pair',
    ['g_v', 'm_g_v_b'])

class Encrypted_Pair(_Encrypted_Pair):
    def __str__(self):
        return f'({self.g_v}, {self.m_g_v_b})'

"""
ElGamal signs one message into as pair of strings.

This class represents the result of signing one message.
"""
_Signed_Pair = namedtuple(
    'Signed_Pair',
    ['r', 's'])

class Signed_Pair(_Signed_Pair):
    def __str__(self):
        return f'(r={self.r}, s={self.s})'

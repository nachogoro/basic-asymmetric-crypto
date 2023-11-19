from collections import namedtuple

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

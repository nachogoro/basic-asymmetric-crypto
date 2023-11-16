"""
Example file to sign a message in the Spanish alphabet using ElGamal.

The default hash function has been used. In order to not use any hash functions, simply remove
the hash_fn parameter to sign
"""

from cryptouned import elgamal
from cryptouned.hashing import sum_hash

alberto = elgamal.ElGamal_Agent(
    name='Alberto',
    private_key=28236)

bono = elgamal.ElGamal_Agent(
    name='Bono',
    private_key=21702)

msg_pair = elgamal.sign('UNED', sender=alberto, receiver=bono, p=15485863, generator=7,
                        h=5, hash_fn=sum_hash, base=27, explain=True)

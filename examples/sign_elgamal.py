"""
Example file to sign a message in the Spanish alphabet using ElGamal.

The default hash function has been used. In order to not use any hash functions, simply set
the hash_fn parameter to None
"""

from cryptouned import elgamal
from cryptouned.hashing import sum_hash

alberto = elgamal.Agent(name='Alberto',
                        private_key=28236)

bono = elgamal.Agent(name='Bono',
                     private_key=21702)

elgamal.sign(msg='UNED',
             sender=alberto,
             receiver=bono,
             p=15485863,
             generator=7,
             h=5,
             hash_fn=sum_hash,
             base=27,
             explain=True)

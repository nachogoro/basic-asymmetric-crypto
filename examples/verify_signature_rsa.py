"""
Example file to sign a message in the Spanish alphabet using RSA.

The default hash function has been used. In order to not use any hash functions, simply set
the hash_fn parameter to None
"""

from cryptouned import rsa
from cryptouned.hashing import sum_hash

alberto = rsa.Agent(name='Alberto',
                    n=34121,
                    e=15775,
                    d=26623)

barbara = rsa.Agent(name='Barbara',
                    n=46927,
                    e=39423,
                    d=26767)

rsa.verify_signature(cryptogram="ACIPAHEP",
                     encrypted_signature="TWW",
                     sender=alberto,
                     receiver=barbara,
                     base=27,
                     hash_fn=sum_hash,
                     explain=True)
"""
Example file to sign a message in the Spanish alphabet using RSA.

The default hash function has been used. In order to not use any hash functions, simply remove
the hash_fn parameter to sign
"""

from cryptouned import rsa
from cryptouned.hashing import sum_hash

# Then define the sender
alberto = rsa.RSA_Agent(
    name='Alberto',
    n=34121,
    e=15775,
    d=26623,
    p=229,
    q=149)

# ... and the receiver
barbara = rsa.RSA_Agent(
    name='Barbara',
    n=46927,
    e=39423)

# Finally, sign the message
rsa.sign(msg='AMOR', sender=alberto, receiver=barbara, base=27, hash_fn=sum_hash, explain=True)

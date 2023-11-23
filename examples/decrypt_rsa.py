"""
Example file to decrypt a message in the Spanish alphabet using RSA
"""

from cryptouned import rsa

alberto = rsa.Agent(name='Alberto',
                    n=34121,
                    e=15775,
                    d=26623)

barbara = rsa.Agent(name='Barbara',
                    n=46927,
                    e=39423,
                    d=26767)

rsa.decrypt(cryptogram="BXOPAQQH",
            sender=alberto,
            receiver=barbara,
            base=27,
            explain=True)

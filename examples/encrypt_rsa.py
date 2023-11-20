"""
Example file to encrypt a message in the Spanish alphabet using RSA
"""

from cryptouned import rsa

# Define the sender
alberto = rsa.Agent(
    name='Alberto',
    n=34121,
    e=15775,
    d=26623,
    p=229,
    q=149)

# ... and the receiver
barbara = rsa.Agent(
    name='Barbara',
    n=46927,
    e=39423,
    d=26767)

# Finally, sign the message
encryption = rsa.encrypt(msg='AMOR', sender=alberto, receiver=barbara, base=27, explain=True)

from rsa_suite import *
import encodingtools

def sum_hash(msg, base, debug):
    # TODO add debug
    result = 0
    for c in msg:
        result = (result + encodingtools.letter_to_number(c, base)) % base

    return encodingtools.number_to_letter(result, base)

# Signing example (january 2015, with hash function)

# Define the sender
alberto = RSA_Agent(
    name='Alberto',
    n=34121,
    e=15775,
    d=26623,
    p=229,
    q=149)

# Define the receiver
barbara = RSA_Agent(
    name='Barbara',
    n=46927,
    e=39423)

# Sign the message
RSA.sign(msg='UNED', sender=alberto, receiver=barbara, base=27,
         hash_fn=sum_hash, debug=True)


print('\n\n\n-------------------\n\n\n')

# Signing example (september 2015, no hash function)
# Define the sender
ali = RSA_Agent(
    name='Ali',
    n=33,
    e=3,
    d=7,
    p=3,
    q=11)

# Define the receiver
bono = RSA_Agent(
    name='Bono',
    n=77,
    e=13)

# Sign the message
RSA.sign(msg='NIÑO', sender=ali, receiver=bono, base=27,
         hash_fn=None, debug=True)

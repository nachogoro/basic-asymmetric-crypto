# Basic asymmetric encryption tools

## Motivation
As part of the subject "Teoría de la información y criptografía básica" in
UNED, students are taught how the main public key encryption schemes (ElGamal
and RSA) work, and are given exercises to encrypt, decrypt and sign messages
using these schemes by hand.

This toolset is designed to help them understand how to properly perform these
calculations, as well as help them ensure their results are correct.

## What does it do?
It gives a simple Python interface to encrypt, decrypt and sign messages using
these assymetric encryption schemes, as well as provide tools to perform the
most common computations (retrieving the GCD of two numbers, raising a number
to a large power, finding the multiplicative modular inverse, etc.).

What is interesting of this project is that every method can be passed a
`debug` flag which will in turn make the method log every single step it
follows to reach the solution. This way, it's easy to see what is going on, and
compare one's answer with the one provided by the toolset, to see where they
diverge.

## How to use it
Every method is documented, so usage should be straight forward.

The methods provided in `mathtools.py` are very straight forward. For example,
see how to compute `7` to the power of `65` modulo `5` using the quick
exponentiation algorithm, step by step:
```python
>>> import mathtools
>>> mathtools.quick_exp(7, 65, 5, debug=True)
r=1           |z=65          |x=7           
r=2           |z=32          |x=4           
r=2           |z=16          |x=1           
r=2           |z=8           |x=1           
r=2           |z=4           |x=1           
r=2           |z=2           |x=1           
r=2           |z=1           |x=1           
r=2           |
2
```

For the encryption schemes defined in `rsa_suite.py` and `elgamal_suite.py`,
one only needs to create the agents of the communication and then invoke the
relevant method:
```python
# Example code for signing with RSA using a hash function which sums the values
# of the digits in a string.
import rsa_suite
import encodingtools

# First define the hash function
def sum_hash(msg, base, debug):
    """
    Hash function which simply sums the values of the characters in the message
    """
    result = 0
    for c in msg:
        result = (result + encodingtools.letter_to_number(c, base)) % base

    return encodingtools.number_to_letter(result, base)

# Then define the sender
alberto = rsa_suite.RSA_Agent(
    name='Alberto',
    n=34121,
    e=15775,
    d=26623,
    p=229,
    q=149)

# ... and the receiver
barbara = rsa_suite.RSA_Agent(
    name='Barbara',
    n=46927,
    e=39423)

# Finally, sign the message
rsa_suite.RSA.sign(msg='UNED', sender=alberto, receiver=barbara, base=27,
         hash_fn=sum_hash, debug=True)
```

```python
# Example code to encrypt with ElGamal
import elgamal_suite
import encodingtools

alberto = elgamal_suite.ElGamal_Agent(
    name='Alberto',
    private_key=28236)

bono = elgamal_suite.ElGamal_Agent(
    name='Bono',
    private_key=21702)

msg_pair = elgamal_suite.ElGamal.encrypt(
    'HIJO', sender=alberto, receiver=bono, p=15485863, generator=7,
    v=480, base=26, debug=True)
```

The code attempts to be as flexible as possible, so that different pieces of
data can be inferred from others. For example, there is no need to specify `n`
for an `RSA_Agent` if `p` and `q` are provided. Also, although for clarity all
methods require a sender and a receiver, since some operations only require one
of them (no need to know who is encrypting a message if it is not signed, for
example), one can specify those parameters as `None` and the code will not
complain.

The code has deliberately been made flexible so that one can give all the data
provided in an exercise and see how to derive the necessary data to perform the
requested task (i.e. to minimize user's work).

## Limitations
* The code is limited to using base 26 (English) or 27 (Spanish, including Ñ).
* For simplicity, the code is case-insensitive when it comes to dealing with
messages.
* The encoding mechanism proposed in the subject assigns the letter A a value
  of 0. This means that a letter A at the beginning of a block to be encrypted
does not affect the resulting cryptogram. Among other things, this means that
it is generally not possible to know if a decrypted message originally
contained a series of 'A' symbols at the beginning.

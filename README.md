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
these asymmetric encryption schemes, as well as provide tools to perform the
most common computations (retrieving the GCD of two numbers, raising a number
to a large power, finding the multiplicative modular inverse, etc.).

What is interesting of this project is that all methods decorated with
`@explaining_method` (which are most of them) can be passed an optional
`explain` flag, which will in turn make the method log every single step it
follows to reach the solution. This way, it's easy to see what is going on, and
compare one's answer with the one provided by the toolset, to see where they
diverge.

## How to use it
### Encrypting, decrypting and signing
In order to perform encryption/decryption and signing operations with RSA and
ElGamal, please see the examples in the `examples/` directory.

You can tweak any of them easily to get the solution to your particular
problem.

### Modular arithmetic
You may be interested in using the library to check certain mathematic
operations. The library may explain, step by step, the following operations:
* Finding the greatest common denominator of two numbers, using Euclides'
  algorithm.
* Raising a number *a* to the power of number *b*, modulo *c*, using the fast
  exponentiation algorithm.
* Finding the multiplicative inverse of a number *a* in modulo *b*, using
  Euclides' extended algorithm.

The following snippets show how to compute each of those operations, all
defined in `cryptouned.utils.modmath`:

```python
from cryptouned.utils.modmath import gcd, inverse, fast_exp

# Compute the greatest common denominator of 65 and 40
gcd(65, 40, explain=True)

# Compute 7^65 mod 13
fast_exp(7,65, 13, explain=True)

# Compute the multiplicative inverse of 13 in 27
inverse(13, 27, explain=True)
```

The `explain=True` flag can be removed, and the methods will simply return the
result without logging any explanation.

## Design philosophy
The principal aim of this project is to be useful to students of the subject.
Hence, it attempts to be as flexible as possible when it comes to solving
exercises with the data given in the exercises. It tries to infer information
reasonably if given, and ignores redudnant pieces of data. For example, there
is no need to specify `n` for an `RSA_Agent` if `p` and `q` are provided. Also,
although for clarity all methods require a sender and a receiver, since some
operations only require one of them (no need to know who is encrypting a
message if it is not signed, for example), one can specify those parameters as
`None` and the code will not complain.

## Limitations and known issues
* The code is limited to using base 26 (English) or 27 (Spanish, including Ñ).
  **Non-letter symbols are not allowed.**
* For simplicity, the code is **case-insensitive** when it comes to dealing
  with messages.
* No method has been provided in the subject to "split" integers into blocks
  when necessary. The library converts the integer to a string for that, but
  other methods may be preferred.
* **RSA signatures may not be verifiable if the receiver's key is shorter than
  the sender's**.

  The sender must split the string message into blocks and transform them with
  their private key to compute the rubric blocks (which are numbers). Each of
  those rubric blocks will be a number between 0 and the sender's n.

  According to the bibliography of the subject, the rubric blocks must be
  *individually* encrypted with the receiver's public key to obtain the
  signature blocks. The criterion used to determine whether a certain rubric
  block is to be split into smaller blocks or not before encrypting it with the
  receiver's public key is to check whether it is larger than the receiver's
  *n* or not.

  If the receiver's *n* is smaller than the sender's *n*, some blocks of the
  rubric may need to be split, while others may not. So each rubric block will
  be split into an indeterminate number of signature blocks.

  In order to verify the signature, the receiver needs to retrieve the rubric
  blocks from the signature blocks. But since each rubric block may have turned
  into a different number of signature blocks, that task is now impossible.

# Author: NachoGoro

from collections import namedtuple
from cryptouned.utils.io_explain import explain, explaining_method
import math
import random

"""
An entry in the table used by the extended Euclides algorithm
"""
Extended_Euclides_Entry = namedtuple(
    'Extended_Euclides_Entry',
    ['y', 'g', 'u', 'v'])


@explaining_method
def gcd(a: int, b: int) -> int:
    """
    Compute the greatest common divisor (GCD) of two integers.

    Uses the Euclidean algorithm to find the largest number that divides both
    `a` and `b` without leaving a remainder.

    Parameters:
    a (int): The first integer.
    b (int): The second integer.

    Returns:
    int: The greatest common divisor of `a` and `b`.
    """
    high = max(a, b)
    low = min(a, b)

    explain('\ngcd({}, {}) = '.format(high, low), end='')

    while low:
        high, low = low, high % low

        explain('gcd({}, {}) = '.format(high, low), end='')

    explain(high)

    return high


@explaining_method
def fast_exp(a: int, b: int, p: int) -> int:
    """
    Calculate the fast exponentiation of `a` to the power of `b` modulo `p`.

    Efficiently computes `a**b mod p` using the method of repeated squaring,
    which is more efficient than straightforward computation for large `b`.

    Parameters:
    a (int): The base number.
    b (int): The exponent.
    p (int): The modulus.

    Returns:
    int: The result of `(a ** b) mod p`.
    """

    explain('\nComputing %d ^ %d (mod %d)' % (a, b, p))

    z = b
    x = a
    r = 1
    while z > 0:
        explain('{0: <14}|{1: <14}|{2: <14}'.format(
            ('r=%d' % r),
            ('z=%d' % z),
            ('x=%d' % x)))

        if z % 2 == 1:
            r = r * x % p
        x = x * x % p
        z //= 2

    explain('{0: <14}|'.format('r=%d' % r))

    return r


@explaining_method
def inverse(a: int, n: int) -> int | None:
    """
    Find the modular multiplicative inverse of `a` modulo `n`.

    Determines the number `x` such that `(a * x) % n == 1`. This function
    returns `None` if no such `x` exists (i.e., if `a` and `n` are not coprime).

    Parameters:
    a (int): The number whose inverse is to be found.
    n (int): The modulus.

    Returns:
    int or None: The modular inverse of `a` modulo `n` if it exists, otherwise `None`.
    """
    explain('\nComputing the multiplicative inverse of %d in %d' % (a, n))

    if gcd(a, n) != 1:
        explain('No inverse: {} and {} are not co-primes'.format(a, n))
        return None
    else:
        explain('%d and %d are co-primes, so the inverse exists\n' % (a, n))

    table = list()
    first_entry = Extended_Euclides_Entry(y=None, g=n, u=1, v=0)
    table.append(first_entry)

    second_entry = Extended_Euclides_Entry(y=None, g=a, u=0, v=1)
    table.append(second_entry)

    i = 2
    while table[i - 1].g != 1:
        y = table[i - 2].g // table[i - 1].g

        table.append(Extended_Euclides_Entry(
            y=y,
            g=table[i - 2].g - y * table[i - 1].g,
            u=table[i - 2].u - y * table[i - 1].u,
            v=table[i - 2].v - y * table[i - 1].v))

        i += 1

    potentially_negative_result = table[i - 1].v
    result = potentially_negative_result % n

    # Print the whole development
    explain('{0: ^10}|{1: ^10}|{2: ^10}|{3: ^10}|{4: ^10}'.format(
        'i', 'y', 'g', 'u', 'v'))
    explain('{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}'.format('-' * 10))
    for i, entry in enumerate(table):
        explain('{0: ^10}|{1: ^10}|{2: ^10}|{3: ^10}|{4: ^10}'.format(
            i, entry.y if entry.y else '--', entry.g, entry.u, entry.v))
        explain('{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}'.format('-' * 10))

    explain('The inverse of %d in %d is then %d mod %d = %d'
            % (a, n, potentially_negative_result, n, result))

    return result


def random_coprime(n: int) -> int:
    """
    Generate a random number that is coprime to `n`.

    Finds a number in the range [2, n) that is coprime to `n`. If `n` is odd,
    it returns a power of two. If `n` is even, it uses a random search to find
    a coprime number.

    Parameters:
    n (int): The number to which the generated number must be coprime.

    Returns:
    int: A random number coprime to `n`.
    """

    if (n % 2) != 0:
        # The number is odd, which means that it will be coprime with any
        # power of two
        max_exp = int(math.log(n, 2))
        random_exp = random.randrange(max_exp)
        return 2 ** random_exp

    candidate = random.randrange(n)

    if (candidate % 2) == 0:
        # The number is even, so no point in trying even candidates
        candidate = (candidate + 1) % n

    if candidate <= 2:
        candidate = 3

    while gcd(n, candidate) != 1:
        # Use steps of 2 to avoid even numbers
        candidate = (candidate + 2) % n

        if candidate <= 2:
            candidate = 3

    return candidate

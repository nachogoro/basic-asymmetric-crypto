# Author: NachoGoro

from collections import namedtuple
from io_explain import explain, explaining_method
import random

"""
An entry in the table used by the extended Euclides algorithm
"""
Extended_Euclides_Entry = namedtuple(
    'Extended_Euclides_Entry',
    ['y', 'g', 'u', 'v'])


@explaining_method
def compute_gcd(a, b):
    """
    Returns the result of: gcd(a, b)
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
def quick_exp(a, b, p):
    """
    Returns the result of: a**b  mod p
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
            r = r*x % p
        x = x*x % p
        z //= 2

    explain('{0: <14}|'.format('r=%d' % r))

    return r


@explaining_method
def get_inverse(a, n):
    """
    Returns the value x which fulfills: x*a = 1 mod n

    If such a value does not exist, it returns None
    """
    explain('\nComputing the multiplicative inverse of %d in %d' % (a, n))

    if compute_gcd(a, n) != 1:
        explain('No inverse: {} and {} are not co-primes'.format(a, n))
        return None
    else:
        explain('%d and %d are coprimes, so the inverse exists\n' % (a, n))

    table = list()
    first_entry = Extended_Euclides_Entry(y=None, g=n, u=1, v=0)
    table.append(first_entry)

    second_entry = Extended_Euclides_Entry(y=None, g=a, u=0, v=1)
    table.append(second_entry)

    i = 2
    while table[i-1].g != 1:
        y = table[i-2].g // table[i-1].g

        table.append(Extended_Euclides_Entry(
            y=y,
            g=table[i-2].g - y*table[i-1].g,
            u=table[i-2].u - y*table[i-1].u,
            v=table[i-2].v - y*table[i-1].v))

        i += 1

    potentially_negative_result = table[i-1].v
    result = potentially_negative_result % n

    # Print the whole development
    explain('{0: ^10}|{1: ^10}|{2: ^10}|{3: ^10}|{4: ^10}'.format(
        'i', 'y', 'g', 'u', 'v'))
    explain('{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}'.format('-'*10))
    for i, entry in enumerate(table):
        explain('{0: ^10}|{1: ^10}|{2: ^10}|{3: ^10}|{4: ^10}'.format(
            i, entry.y if entry.y else '--', entry.g, entry.u, entry.v))
        explain('{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}'.format('-'*10))

    explain('The inverse of %d in %d is then %d mod %d = %d'
            % (a, n, potentially_negative_result, n, result))

    return result


def get_coprime_in_range(n):
    """
    Returns a number in the range [2-n) which is coprime with n
    """
    if (n % 2) != 0:
        # The number is odd, which means that it will be coprime with any
        # power of two
        max_exp = int(math.log(n, 2))
        random_exp = random.randrange(max_exp)
        return 2**random_exp

    candidate = random.randrange(n)

    if (candidate % 2) == 0:
        # The number is even, so no point in trying even candidates
        candidate = (candidate + 1) % n

    if candidate <= 2:
        candidate = 3

    while compute_gcd(n, candidate) != 1:
        # Use steps of 2 to avoid even numbers
        candidate = (candidate + 2) % n

        if candidate <= 2:
            candidate = 3

    return candidate

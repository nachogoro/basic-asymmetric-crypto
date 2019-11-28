# Author: NachoGoro

from collections import namedtuple

Extended_Euclided_Entry = namedtuple(
    'Extended_Euclided_Entry',
    ['y', 'g', 'u', 'v'])


def compute_gcd(a, b, debug=False):
    """
    Returns the result of: gcd(a, b)
    """
    high = max(a, b)
    low = min(a, b)

    if debug:
        print('gcd({}, {}) = '.format(high, low), end='')

    while(low):
        high, low = low, high % low

        if debug:
            print('gcd({}, {}) = '.format(high, low), end='')

    if debug:
        print(high)

    return high


def quick_exp(a, b, p, debug=False):
    """
    Returns the result of: a**b  mod p
    """
    z = b
    x = a
    r = 1
    while z > 0:
        if debug:
            print('{0: <14}|{1: <14}|{2: <14}'.format(
                ('r=%d' % r),
                ('z=%d' % z),
                ('x=%d' % x)))

        if z % 2 == 1:
            r = r*x % p
        x = x*x % p
        z //= 2

    if debug:
        print('{0: <14}|'.format('r=%d' % r))

    return r


def get_inverse(a, n, debug=False):
    """
    Returns the value x which fulfills: x*a = 1 mod n

    If such a value does not exist, it returns None
    """
    if compute_gcd(a, n, debug) != 1:
        if debug:
            print('No inverse: {} and {} are not co-primes'.format(a, n))
        return None

    table = list()
    first_entry = Extended_Euclided_Entry(y=None, g=n, u=1, v=0)
    table.append(first_entry)

    second_entry = Extended_Euclided_Entry(y=None, g=a, u=0, v=1)
    table.append(second_entry)

    i = 2
    while table[i-1].g != 0:
        y = table[i-2].g // table[i-1].g

        table.append(Extended_Euclided_Entry(
            y=y,
            g=table[i-2].g - y*table[i-1].g,
            u=table[i-2].u - y*table[i-1].u,
            v=table[i-2].v - y*table[i-1].v))

        i += 1

    if debug:
        # Print the whole development
        print('{0: ^10}|{1: ^10}|{2: ^10}|{3: ^10}|{4: ^10}'.format(
            'i', 'y', 'g', 'u', 'v'))
        print('{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}'.format('-'*10))
        for i, entry in enumerate(table):
            print('{0: ^10}|{1: ^10}|{2: ^10}|{3: ^10}|{4: ^10}'.format(
                i, entry.y if entry.y else '--', entry.g, entry.u, entry.v))
            print('{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}|{0: ^10}'.format('-'*10))

    return(table[i-2].v % n)

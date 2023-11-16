from cryptouned.utils.modmath import gcd, inverse, fast_exp

# Compute the greatest common denominator of 65 and 40
gcd(65, 40, explain=True)

# Compute 7^65 mod 13
fast_exp(7,65, 13, explain=True)

# Compute the multiplicative inverse of 13 in 27
inverse(13, 27, explain=True)

"""
Example file to encrypt a message in the Spanish alphabet using ElGamal
"""
from cryptouned import elgamal

alberto = elgamal.ElGamal_Agent(
    name='Alicia',
    private_key=28236)

bono = elgamal.ElGamal_Agent(
    name='Bob',
    private_key=21702)

msg_pair = elgamal.encrypt(
    'UNED', sender=alberto, receiver=bono, p=15485863, generator=7,
    v=480, base=27, explain=True)


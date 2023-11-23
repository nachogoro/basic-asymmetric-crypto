"""
Example file to encrypt a message in the Spanish alphabet using ElGamal
"""
from cryptouned import elgamal
from cryptouned.utils.elgamal_types import EncryptedPair

alicia = elgamal.Agent(name='Alicia',
                       private_key=28236)

bob = elgamal.Agent(name='Bob',
                    private_key=21702)

elgamal.decrypt(cryptogram_pair=EncryptedPair("KVITZ", "BBKDDU"),
                sender=alicia,
                receiver=bob,
                p=15485863,
                generator=7,
                base=27,
                explain=True)

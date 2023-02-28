from Crypto.PublicKey import RSA
from hashlib import sha256

keyPair = RSA.generate(bits=1024)
print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")
msg = b'nguyen ngoc khanh'

hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
print(hash)
signature = pow(hash, keyPair.d, keyPair.n)
print("Signature:", hex(signature))

#verify 
msg = b'nguyen ngoc khanh'
hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
hashFromSignature = pow(signature, keyPair.e, keyPair.n)
print("Signature valid:", hash == hashFromSignature)

#fake
msg = b'nguyen ngoc khanh fake'
hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
hashFromSignature = pow(signature, keyPair.e, keyPair.n)
print("Signature valid (fake):", hash == hashFromSignature)
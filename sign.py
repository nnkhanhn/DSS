from Crypto.PublicKey import RSA
from hashlib import sha256
def key_generate():
    keyPair = RSA.generate(bits=1024)
    # print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    # print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")
    return keyPair

def sig_generate(keyPair,msg):
    hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
    # print(hash)
    signature = pow(hash, keyPair.d, keyPair.n)
    # print("Signature:", hex(signature))
    return signature


while(True):
    print("------------simulation--------------")
    msg = str(input("Input message: "))
    msg = msg.encode()
    keyPair = key_generate()
    signature = sig_generate(keyPair, msg)
    #attacking
    atk = str(input("Attack ?('y' or 'n'): "))

    if atk == 'n':
       hash = int.from_bytes(sha256(msg).digest(), byteorder='big') 
       hashFromSignature = pow(signature, keyPair.e, keyPair.n)
       print("Signature valid:", hash == hashFromSignature)

    if atk == 'y':
        msg2 = msg + b"asdwdeefaf"
        hash = int.from_bytes(sha256(msg2).digest(), byteorder='big') 
        hashFromSignature = pow(signature, keyPair.e, keyPair.n)
        print("Signature valid:", hash == hashFromSignature)
    print("Continue ?")
    ctn = str(input())
    if ctn == 'n':
        break

# #verify 
# msg = b'nguyen ngoc khanh'
# hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
# hashFromSignature = pow(signature, keyPair.e, keyPair.n)
# print("Signature valid:", hash == hashFromSignature)

# #fake
# msg = b'nguyen ngoc khanh fake'
# hash = int.from_bytes(sha256(msg).digest(), byteorder='big')
# hashFromSignature = pow(signature, keyPair.e, keyPair.n)
# print("Signature valid (fake):", hash == hashFromSignature)

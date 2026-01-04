import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

with open("python_ciphertext_enc.bin", "rb") as f:
    enc_key = f.read(256)
    enc_iv = f.read(256)
    enc_hmac = f.read(256)
    ciphertext = f.read()

open("enc_key.bin", "wb").write(enc_key)
open("enc_iv.bin", "wb").write(enc_iv)
open("enc_hmac.bin", "wb").write(enc_hmac)
open("ciphertext_data.bin", "wb").write(ciphertext)

with open("receiver_private_key.pem", "rb") as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=b"lab1enckeys"
    )


def rsa_decrypt(data, key):
    return key.decrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )


aes_key = rsa_decrypt(enc_key, private_key)
iv = rsa_decrypt(enc_iv, private_key)
hmac_key = rsa_decrypt(enc_hmac, private_key)


cipher = Cipher(
    algorithms.AES(aes_key),
    modes.CBC(iv)
)

decryptor = cipher.decryptor()
padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

unpadder = sym_padding.PKCS7(128).unpadder()
plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

open("plaintext.txt", "wb").write(plaintext)

mac = hmac.new(hmac_key, plaintext, hashlib.md5).digest()
print(mac.hex())

with open("sender_certificate.pem", "rb") as f:
    cert = x509.load_pem_x509_certificate(f.read())

public_key = cert.public_key()
with open("sender_signature_1.bin", "rb") as f:
    signature = f.read()

try:
    public_key.verify(
        signature,
        plaintext,
        padding.PKCS1v15(),
        hashes.SHA1()
    )
    print("Signature is valid")
except BaseException:
    print("Signature is invalid")

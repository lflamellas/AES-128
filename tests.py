from modes import aes_ecb_encryption, aes_ecb_decryption, aes_ctr_encryption, aes_ctr_decryption, pad
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB, CTR

with open('data.txt', 'r') as file:
    data = file.read().rstrip()

plaintext = pad(data)
key = "aesEncryptionKey"
iv = 2623891

aes_ecb_cipher = Cipher(AES(key.encode('utf-8')), ECB())
aes_ctr_cipher = Cipher(AES(key.encode('utf-8')), CTR(iv.to_bytes(16, 'big')))

ecb_cipher = aes_ecb_encryption(plaintext, key).hex()
ecb_decrypted = aes_ecb_decryption(ecb_cipher, key).decode()

ctr_cipher = aes_ctr_encryption(plaintext, key, iv).hex()
ctr_decrypted = aes_ctr_decryption(ctr_cipher, key, iv).decode()

expected_ecb_ciphertext = aes_ecb_cipher.encryptor().update(plaintext.encode('utf-8')).hex()
expected_ctr_ciphertext = aes_ctr_cipher.encryptor().update(plaintext.encode('utf-8')).hex()

print("****** ECB CIPHER ******")
print("Output  : ", ecb_cipher)
print("Expected: ", expected_ecb_ciphertext)
print()

assert(ecb_cipher == expected_ecb_ciphertext)

print("****** CTR CIPHER ******")
print("Output  : ", ctr_cipher)
print("Expected: ", expected_ctr_ciphertext)
print()

assert(ctr_cipher == expected_ctr_ciphertext)

print("****** DECRYPTION ******")
print("ECB  : ", ecb_decrypted)
print("CTR  : ", ctr_decrypted)
print()

assert(ecb_decrypted == plaintext)
assert(ctr_decrypted == plaintext)
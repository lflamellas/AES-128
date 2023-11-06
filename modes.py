from aes import aes_encryption, aes_decryption, xor_bytes

BLOCK_SIZE = 16

def pad(text: [chr]) -> [chr]:
  if (len(text) % BLOCK_SIZE) == 0:
    return text
  pad_size = BLOCK_SIZE - len(text) % BLOCK_SIZE
  return text + " " * pad_size

def aes_ecb_encryption(plaintext: [chr], key: [chr]) -> bytes:
  data = pad(plaintext)
  data = data.encode('utf-8')
  key = key.encode('utf-8')
  cipher = []
  for i in range(len(data) // BLOCK_SIZE):
    block = data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
    encrypted_block = aes_encryption(block, key)
    cipher += encrypted_block
  return bytes(cipher)
  
def aes_ecb_decryption(ciphertext: [chr], key: [chr]) -> bytes:
  data = bytearray.fromhex(ciphertext)
  key = key.encode('utf-8')
  plaintext = []
  for i in range(len(data) // BLOCK_SIZE):
    block = data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
    decrypted_block = aes_decryption(block, key)
    plaintext += decrypted_block
  return bytes(plaintext)
  
def aes_ctr_encryption(plaintext: [chr], key: [chr], iv: int) -> bytes:
  data = pad(plaintext)
  data = data.encode('utf-8')
  key = key.encode('utf-8')
  cipher = []
  for i in range(len(data) // BLOCK_SIZE):
      block = data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
      encrypted_block = aes_encryption(iv.to_bytes(16, 'big'), key)
      cipher += xor_bytes(encrypted_block, block)
      iv += 1
  return bytes(cipher)


def aes_ctr_decryption(ciphertext: [chr], key: [chr], iv: int) -> bytes:
    data = bytearray.fromhex(ciphertext)
    key = key.encode('utf-8')
    plaintext = []
    for i in range(len(data) // BLOCK_SIZE):
        block = data[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE]
        decrypted_block = aes_encryption(iv.to_bytes(16, 'big'), key)
        plaintext += xor_bytes(decrypted_block , block)
        iv += 1
    return bytes(plaintext)

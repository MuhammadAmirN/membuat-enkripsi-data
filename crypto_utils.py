from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# 🔐 AES ENKRIPSI
def encrypt_file_aes(file_data):
    key = get_random_bytes(16)  # 128-bit AES key
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(file_data)
    return key, cipher.nonce, tag, ciphertext

# 🔓 AES DEKRIPSI
def decrypt_file_aes(key, nonce, tag, ciphertext):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# 🔐 GENERATE RSA KEY
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# 🔒 ENKRIPSI AES KEY DENGAN PUBLIC RSA
def encrypt_key_rsa(aes_key, public_key_bytes):
    if isinstance(public_key_bytes, bytes):
        public_key = RSA.import_key(public_key_bytes)
    elif isinstance(public_key_bytes, RSA.RsaKey):
        public_key = public_key_bytes
    else:
        raise TypeError("Public key harus berupa bytes atau RSA.RsaKey")
    
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(aes_key)

# 🔓 DEKRIPSI AES KEY DENGAN PRIVATE RSA
def decrypt_key_rsa(encrypted_key, private_key):
    if isinstance(private_key, bytes):
        private_key = RSA.import_key(private_key)
    elif not isinstance(private_key, RSA.RsaKey):
        raise TypeError("Private key harus berupa bytes atau RSA.RsaKey")

    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

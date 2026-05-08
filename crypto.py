"""Ce fichier contient tous les codes de cryptages fait en classes"""
#  FONCTIONS COMMUNES
def _int_to_bytes(n: int, length: int) :
    return n.to_bytes(length, byteorder="big")
 
 
def _bytes_to_bin(data: bytes, width: int | None = None):
    result = bin(int.from_bytes(data, byteorder="big"))[2:]
    if width:
        result = result.zfill(width)
    return result
 
 
def _int_to_bin(n: int, width: int) :
    return bin(n)[2:].zfill(width)
 
 
def _bin_to_int(b: str):
    return int(b, 2)
 
 
def _rotate_left(n: int, shift: int, bit_size: int) :
    return ((n << shift) | (n >> (bit_size - shift))) & ((1 << bit_size) - 1)
 
"""SHA1"""
def sha1(message: bytes) :
 
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
 
    #padding
    msg = bytearray(message)
    original_length_bits = len(message) * 8
    # bit '1' (0x80)
    msg.append(0x80)
    # padding 448 mod 512 bits
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    # padding 
    msg += original_length_bits.to_bytes(8, byteorder="big")
    # Boucle par blocs de 512 bits 
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        # Découp 16 w of 32 bits
        w = [int.from_bytes(block[j:j + 4], byteorder="big") for j in range(0, 64, 4)]
        # 80 w
        for j in range(16, 80):
            val = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
            w.append(_rotate_left(val, 1, 32))
        a, b, c, d, e = h0, h1, h2, h3, h4
 
        for j in range(80):
            if 0 <= j <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= j <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= j <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d
                k = 0xCA62C1D6
 
            temp = (_rotate_left(a, 5, 32) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d
            d = c
            c = _rotate_left(b, 30, 32)
            b = a
            a = temp
 
        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
 
    return "%08x%08x%08x%08x%08x" % (h0, h1, h2, h3, h4)

"""sha256:"""
#first prime numbers
_SHA256_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]
_SHA256_H0 = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]
 
 
def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF
 
 
def sha256(message: bytes) -> str:
    h = list(_SHA256_H0)
 
    #padding
    msg = bytearray(message)
    original_length_bits = len(message) * 8
 
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += original_length_bits.to_bytes(8, byteorder="big")
 
    # blocs de 512 bits 
    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
 
        # 16 w of 32 bits
        w = [int.from_bytes(block[j:j + 4], byteorder="big") for j in range(0, 64, 4)]
 
        # padding 2 64 w
        for j in range(16, 64):
            s0 = _rotr32(w[j-15], 7) ^ _rotr32(w[j-15], 18) ^ (w[j-15] >> 3)
            s1 = _rotr32(w[j-2], 17) ^ _rotr32(w[j-2],  19) ^ (w[j-2] >> 10)
            w.append((w[j-16] + s0 + w[j-7] + s1) & 0xFFFFFFFF)
 
        a, b, c, d, e, f, g, hh = h
 
        for j in range(64):
            S1    = _rotr32(e, 6) ^ _rotr32(e, 11) ^ _rotr32(e, 25)
            ch    = (e & f) ^ ((~e) & g)
            temp1 = (hh + S1 + ch + _SHA256_K[j] + w[j]) & 0xFFFFFFFF
            S0    = _rotr32(a, 2) ^ _rotr32(a, 13) ^ _rotr32(a, 22)
            maj   = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xFFFFFFFF
 
            hh = g; g = f; f = e
            e  = (d + temp1) & 0xFFFFFFFF
            d  = c; c = b; b = a
            a  = (temp1 + temp2) & 0xFFFFFFFF
 
        new_h = [a, b, c, d, e, f, g, hh]
        h = [(h[j] + new_h[j]) & 0xFFFFFFFF for j in range(8)]
 
    return "".join("%08x" % x for x in h)

"""RC4"""
def rc4(key: bytes, data: bytes) :
    # Initialisation de S
    S = list(range(256))
    j = 0
    key_len = len(key)
 
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) % 256
        S[i], S[j] = S[j], S[i]
 
    
    result = []
    i = j = 0
 
    for byte in data:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        result.append(byte ^ k)
 
    return bytes(result)

"""DES"""
IP = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
]
IP_INV = [
    40,  8, 48, 16, 56, 24, 64, 32,
    39,  7, 47, 15, 55, 23, 63, 31,
    38,  6, 46, 14, 54, 22, 62, 30,
    37,  5, 45, 13, 53, 21, 61, 29,
    36,  4, 44, 12, 52, 20, 60, 28,
    35,  3, 43, 11, 51, 19, 59, 27,
    34,  2, 42, 10, 50, 18, 58, 26,
    33,  1, 41,  9, 49, 17, 57, 25,
]

PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

E_TABLE = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]

P_TABLE = [
    16,  7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26,  5, 18, 31, 10,
     2,  8, 24, 14, 32, 27,  3,  9,
    19, 13, 30,  6, 22, 11,  4, 25,
]
 

SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
S_BOX = [
    # S1
    [
        [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
        [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
        [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
        [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    # S2
    [
        [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
        [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
        [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
        [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    # S3
    [
        [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
        [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
        [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
        [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    # S4
    [
        [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
        [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
        [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
        [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    # S5
    [
        [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9],
        [14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6],
        [ 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
        [11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    # S6
    [
        [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
        [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
        [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
        [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    # S7
    [
        [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
        [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
        [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
        [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    # S8
    [
        [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
        [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
        [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
        [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ],
]
 
 
 
def _permute(block: str, table: list[int]):
    return "".join(block[i - 1] for i in table)
 
 
def IP(block: str) -> str:
    return _permute(block, [
        58, 50, 42, 34, 26, 18, 10,  2,
        60, 52, 44, 36, 28, 20, 12,  4,
        62, 54, 46, 38, 30, 22, 14,  6,
        64, 56, 48, 40, 32, 24, 16,  8,
        57, 49, 41, 33, 25, 17,  9,  1,
        59, 51, 43, 35, 27, 19, 11,  3,
        61, 53, 45, 37, 29, 21, 13,  5,
        63, 55, 47, 39, 31, 23, 15,  7,
    ])
 
 
def IP_INV(block: str) -> str:
    return _permute(block, [
        40,  8, 48, 16, 56, 24, 64, 32,
        39,  7, 47, 15, 55, 23, 63, 31,
        38,  6, 46, 14, 54, 22, 62, 30,
        37,  5, 45, 13, 53, 21, 61, 29,
        36,  4, 44, 12, 52, 20, 60, 28,
        35,  3, 43, 11, 51, 19, 59, 27,
        34,  2, 42, 10, 50, 18, 58, 26,
        33,  1, 41,  9, 49, 17, 57, 25,
    ])
 
 
def C(key56: str) -> str:
    return key56[:28]
 
 
def D(key56: str):
    return key56[28:]
 
 
def generate_keys(key: bytes):
    key_bin = _bytes_to_bin(key, 64)
    key56 = _permute(key_bin, PC1)
    c = C(key56)
    d = D(key56)
 
    subkeys = []
    for shift in SHIFT_SCHEDULE:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        cd = c + d
        subkeys.append(_permute(cd, PC2))
 
    return subkeys
def Expansion(half_block: str) :
    return _permute(half_block, E_TABLE)
 
 
def XOR(a: str, b: str) :
    return "".join("0" if x == y else "1" for x, y in zip(a, b))
 
 
def Substitution(block48: str):
    result = ""
    for i in range(8):
        group = block48[i * 6:(i + 1) * 6]
        row = _bin_to_int(group[0] + group[5])# bits ext
        col = _bin_to_int(group[1:5])# bits int
        val = S_BOX[i][row][col]
        result += _int_to_bin(val, 4)
    return result
 
 
def Permutation(block32: str) :
    return _permute(block32, P_TABLE)
 
 
def f_function(right: str, subkey: str) :
    expanded  = Expansion(right)
    xored     = XOR(expanded, subkey)
    subst     = Substitution(xored)
    permuted  = Permutation(subst)
    return permuted
 
 
def encrypt(plaintext: bytes, key: bytes, mode: str = "encrypt") :
    if len(plaintext) != 8:
        raise ValueError("Le bloc DES doit faire exactement 8 octets.")
    if len(key) != 8:
        raise ValueError("La clé DES doit faire exactement 8 octets.")
 
    # Génération des 16 sous-clés
    subkeys = generate_keys(key)
    if mode == "decrypt":
        subkeys = subkeys[::-1]  # Ordre inversé pour le déchiffrement
 
    # Bloc en binaire (64 bits)
    block = _bytes_to_bin(plaintext, 64)
 
    # Permutation initiale
    block = IP(block)
 
    # Division en 2 1/2 de 32 bits
    left  = block[:32]
    right = block[32:]
 
    # 16 rounds de Feistel
    for subkey in subkeys:
        new_right = XOR(left, f_function(right, subkey))
        left  = right
        right = new_right
 
    combined = right + left

    result = IP_INV(combined)
 
    return _int_to_bytes(_bin_to_int(result), 8)

#Padding PKCS7
def _pkcs7_pad(data: bytes, block_size: int):
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)
 
 
def _pkcs7_unpad(data: bytes):
    if not data:
        return data
    pad_len = data[-1]
    return data[:-pad_len]

def cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes):
    if len(iv) != 8:
        raise ValueError("L'IV doit faire exactement 8 octets.")
 
    padded = _pkcs7_pad(plaintext, 8)
 
    ciphertext = b""
    register   = iv
 
    for i in range(0, len(padded), 8):
        block     = padded[i:i + 8]
        encrypted = encrypt(register, key, mode="encrypt")
        cipher_block = bytes(a ^ b for a, b in zip(encrypted, block))
        ciphertext  += cipher_block
        register     = cipher_block   # feedback
 
    return ciphertext
 
 
def cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes):
    if len(iv) != 8:
        raise ValueError("L'IV doit faire exactement 8 octets.")
 
    plaintext = b""
    register  = iv
 
    for i in range(0, len(ciphertext), 8):
        block        = ciphertext[i:i + 8]
        encrypted    = encrypt(register, key, mode="encrypt") 
        plain_block  = bytes(a ^ b for a, b in zip(encrypted, block))
        plaintext   += plain_block
        register     = block 
 
    return _pkcs7_unpad(plaintext)









 
 

def hash_password(password: str,salt) -> tuple[str, str]:
    """ 
    Hash un mot de passe avec SHA-256 + salt aléatoire.
 
    Mécanisme :
        1. Génère un salt de 32 octets aléatoires (os.urandom)
        2. Concatène  salt + password  en bytes
        3. Passe le tout dans notre sha256() fait en classe
        4. Retourne (hash_hex, salt_hex)  — les deux sont stockés en DB
 
    Retourne :
        (password_hash, salt)  — deux strings hexadécimales """
    
    salt_hex      = salt.hex()                      # stocké en DB tel quel
 
    salted        = salt + password.encode("utf-8") # salt + mdp en bytes
    password_hash = sha256(salted)                        # notre sha256 maison
 
    return password_hash, salt_hex
""" 
def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    Vérifie qu'un mot de passe correspond au hash stocké en DB.
 
    Mécanisme :
        Recrée exactement la même opération que hash_password() :
        sha256(salt_bytes + password_bytes)
        et compare le résultat au hash stocké.
 
    Paramètres :
        password    — mot de passe saisi par l'utilisateur
        stored_hash — password_hash récupéré depuis la DB
        stored_salt — salt récupéré depuis la DB
 
    Retourne :
        True si le mot de passe est correct, False sinon.
    salt_bytes    = bytes.fromhex(stored_salt)
    salted        = salt_bytes + password.encode("utf-8")
    computed_hash = sha256(salted)
 
    return computed_hash == stored_hash
"""
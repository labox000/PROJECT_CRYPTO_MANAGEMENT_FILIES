"""
crypto.py — Tous les algorithmes de chiffrement et de hachage, implémentés from scratch.

Algorithmes de hachage  : SHA-1, SHA-256
Algorithmes symétriques : DES (CFB), 3DES (CFB), AES (CBC), ChaCha20
Algorithmes asymétriques: RSA, ElGamal

Point d'entrée unifié   : encrypt(data, mode) / decrypt(data, metadata)
Sélection interactive   : prompt_crypto_mode()
Hachage mot de passe    : hash_password(password, salt) / verify_password(...)
Intégrité fichier       : compute_integrity_hash(data)
"""

import os
import json
import secrets

# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITAIRES BINAIRES COMMUNS
# ═══════════════════════════════════════════════════════════════════════════════

def _int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, byteorder="big")

def _bytes_to_int(data: bytes) -> int:
    return int.from_bytes(data, byteorder="big")

def _bytes_to_bin(data: bytes, width: int | None = None) -> str:
    result = bin(int.from_bytes(data, byteorder="big"))[2:]
    if width:
        result = result.zfill(width)
    return result

def _int_to_bin(n: int, width: int) -> str:
    return bin(n)[2:].zfill(width)

def _bin_to_int(b: str) -> int:
    return int(b, 2)

def _rotate_left(n: int, shift: int, bit_size: int) -> int:
    return ((n << shift) | (n >> (bit_size - shift))) & ((1 << bit_size) - 1)

def _rotr32(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def _rotr64(x: int, n: int) -> int:
    return ((x >> n) | (x << (64 - n))) & 0xFFFFFFFFFFFFFFFF

def _pkcs7_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        return data
    pad_len = data[-1]
    if pad_len == 0 or pad_len > 16:
        return data
    return data[:-pad_len]

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ═══════════════════════════════════════════════════════════════════════════════
#  SHA-1
# ═══════════════════════════════════════════════════════════════════════════════

def sha1(message: bytes) -> str:
    """Retourne le hash SHA-1 du message sous forme hexadécimale."""
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    msg = bytearray(message)
    original_length_bits = len(message) * 8
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += original_length_bits.to_bytes(8, byteorder="big")

    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        w = [int.from_bytes(block[j:j + 4], byteorder="big") for j in range(0, 64, 4)]
        for j in range(16, 80):
            val = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
            w.append(_rotate_left(val, 1, 32))

        a, b, c, d, e = h0, h1, h2, h3, h4
        for j in range(80):
            if j <= 19:
                f = (b & c) | ((~b) & d); k = 0x5A827999
            elif j <= 39:
                f = b ^ c ^ d;            k = 0x6ED9EBA1
            elif j <= 59:
                f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDC
            else:
                f = b ^ c ^ d;            k = 0xCA62C1D6

            temp = (_rotate_left(a, 5, 32) + f + e + k + w[j]) & 0xFFFFFFFF
            e = d; d = c; c = _rotate_left(b, 30, 32); b = a; a = temp

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF

    return "%08x%08x%08x%08x%08x" % (h0, h1, h2, h3, h4)


# ═══════════════════════════════════════════════════════════════════════════════
#  SHA-256
# ═══════════════════════════════════════════════════════════════════════════════

_SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]
_SHA256_H0 = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]

def sha256(message: bytes) -> str:
    """Retourne le hash SHA-256 du message sous forme hexadécimale."""
    h = list(_SHA256_H0)
    msg = bytearray(message)
    original_length_bits = len(message) * 8
    msg.append(0x80)
    while (len(msg) * 8) % 512 != 448:
        msg.append(0x00)
    msg += original_length_bits.to_bytes(8, byteorder="big")

    for i in range(0, len(msg), 64):
        block = msg[i:i + 64]
        w = [int.from_bytes(block[j:j + 4], byteorder="big") for j in range(0, 64, 4)]
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


# ═══════════════════════════════════════════════════════════════════════════════
#  DES — tables et fonctions internes
# ═══════════════════════════════════════════════════════════════════════════════

_IP_TABLE = [
    58,50,42,34,26,18,10, 2, 60,52,44,36,28,20,12, 4,
    62,54,46,38,30,22,14, 6, 64,56,48,40,32,24,16, 8,
    57,49,41,33,25,17, 9, 1, 59,51,43,35,27,19,11, 3,
    61,53,45,37,29,21,13, 5, 63,55,47,39,31,23,15, 7,
]
_IP_INV_TABLE = [
    40, 8,48,16,56,24,64,32, 39, 7,47,15,55,23,63,31,
    38, 6,46,14,54,22,62,30, 37, 5,45,13,53,21,61,29,
    36, 4,44,12,52,20,60,28, 35, 3,43,11,51,19,59,27,
    34, 2,42,10,50,18,58,26, 33, 1,41, 9,49,17,57,25,
]
_PC1 = [
    57,49,41,33,25,17, 9,  1,58,50,42,34,26,18,
    10, 2,59,51,43,35,27, 19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15,  7,62,54,46,38,30,22,
    14, 6,61,53,45,37,29, 21,13, 5,28,20,12, 4,
]
_PC2 = [
    14,17,11,24, 1, 5,  3,28,15, 6,21,10,
    23,19,12, 4,26, 8, 16, 7,27,20,13, 2,
    41,52,31,37,47,55, 30,40,51,45,33,48,
    44,49,39,56,34,53, 46,42,50,36,29,32,
]
_E_TABLE = [
    32, 1, 2, 3, 4, 5,  4, 5, 6, 7, 8, 9,
     8, 9,10,11,12,13, 12,13,14,15,16,17,
    16,17,18,19,20,21, 20,21,22,23,24,25,
    24,25,26,27,28,29, 28,29,30,31,32, 1,
]
_P_TABLE = [
    16, 7,20,21,29,12,28,17,
     1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,
    19,13,30, 6,22,11, 4,25,
]
_DES_SHIFT = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]
_S_BOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
]

def _permute(block: str, table: list) -> str:
    return "".join(block[i - 1] for i in table)

def _des_generate_subkeys(key: bytes) -> list:
    key_bin = _bytes_to_bin(key, 64)
    key56   = _permute(key_bin, _PC1)
    c, d    = key56[:28], key56[28:]
    subkeys = []
    for shift in _DES_SHIFT:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        subkeys.append(_permute(c + d, _PC2))
    return subkeys

def _des_f(right: str, subkey: str) -> str:
    expanded = _permute(right, _E_TABLE)
    xored    = "".join("0" if a == b else "1" for a, b in zip(expanded, subkey))
    result   = ""
    for i in range(8):
        group = xored[i*6:(i+1)*6]
        row   = _bin_to_int(group[0] + group[5])
        col   = _bin_to_int(group[1:5])
        result += _int_to_bin(_S_BOX[i][row][col], 4)
    return _permute(result, _P_TABLE)

def _des_encrypt_block(plaintext: bytes, key: bytes, mode: str = "encrypt") -> bytes:
    """Chiffre ou déchiffre un bloc de 8 octets avec DES."""
    if len(plaintext) != 8:
        raise ValueError("Bloc DES : exactement 8 octets requis.")
    if len(key) != 8:
        raise ValueError("Clé DES : exactement 8 octets requis.")

    subkeys = _des_generate_subkeys(key)
    if mode == "decrypt":
        subkeys = subkeys[::-1]

    block = _bytes_to_bin(plaintext, 64)
    block = _permute(block, _IP_TABLE)
    left, right = block[:32], block[32:]

    for subkey in subkeys:
        new_right = "".join("0" if a == b else "1" for a, b in zip(left, _des_f(right, subkey)))
        left, right = right, new_right

    result = _permute(right + left, _IP_INV_TABLE)
    return _int_to_bytes(_bin_to_int(result), 8)


def _des_cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded     = _pkcs7_pad(plaintext, 8)
    ciphertext = b""
    register   = iv
    for i in range(0, len(padded), 8):
        block        = padded[i:i+8]
        encrypted    = _des_encrypt_block(register, key, "encrypt")
        cipher_block = _xor_bytes(encrypted, block)
        ciphertext  += cipher_block
        register     = cipher_block
    return ciphertext

def _des_cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = b""
    register  = iv
    for i in range(0, len(ciphertext), 8):
        block       = ciphertext[i:i+8]
        encrypted   = _des_encrypt_block(register, key, "encrypt")
        plain_block = _xor_bytes(encrypted, block)
        plaintext  += plain_block
        register    = block
    return _pkcs7_unpad(plaintext)


# ═══════════════════════════════════════════════════════════════════════════════
#  3DES — Triple DES (EDE : Encrypt-Decrypt-Encrypt avec 3 clés de 8 octets)
# ═══════════════════════════════════════════════════════════════════════════════

def _3des_encrypt_block(plaintext: bytes, key: bytes, mode: str = "encrypt") -> bytes:
    """
    Clé de 24 octets = k1(8) + k2(8) + k3(8).
    Mode EDE : E(k1) → D(k2) → E(k3) pour chiffrer
               D(k3) → E(k2) → D(k1) pour déchiffrer
    """
    if len(key) != 24:
        raise ValueError("Clé 3DES : exactement 24 octets requis.")
    k1, k2, k3 = key[:8], key[8:16], key[16:]
    if mode == "encrypt":
        block = _des_encrypt_block(plaintext, k1, "encrypt")
        block = _des_encrypt_block(block,     k2, "decrypt")
        block = _des_encrypt_block(block,     k3, "encrypt")
    else:
        block = _des_encrypt_block(plaintext, k3, "decrypt")
        block = _des_encrypt_block(block,     k2, "encrypt")
        block = _des_encrypt_block(block,     k1, "decrypt")
    return block

def _3des_cfb_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    padded     = _pkcs7_pad(plaintext, 8)
    ciphertext = b""
    register   = iv
    for i in range(0, len(padded), 8):
        block        = padded[i:i+8]
        encrypted    = _3des_encrypt_block(register, key, "encrypt")
        cipher_block = _xor_bytes(encrypted, block)
        ciphertext  += cipher_block
        register     = cipher_block
    return ciphertext

def _3des_cfb_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    plaintext = b""
    register  = iv
    for i in range(0, len(ciphertext), 8):
        block       = ciphertext[i:i+8]
        encrypted   = _3des_encrypt_block(register, key, "encrypt")
        plain_block = _xor_bytes(encrypted, block)
        plaintext  += plain_block
        register    = block
    return _pkcs7_unpad(plaintext)


# ═══════════════════════════════════════════════════════════════════════════════
#  AES-128 — mode CBC
# ═══════════════════════════════════════════════════════════════════════════════

_AES_SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]
_AES_SBOX_INV = [0] * 256
for _i, _v in enumerate(_AES_SBOX):
    _AES_SBOX_INV[_v] = _i

_AES_RCON = [0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]

def _gf_mul(a: int, b: int) -> int:
    """Multiplication dans GF(2^8) avec polynôme irréductible 0x11b."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1b
        b >>= 1
    return p

def _aes_sub_bytes(state: list) -> list:
    return [[_AES_SBOX[b] for b in row] for row in state]

def _aes_sub_bytes_inv(state: list) -> list:
    return [[_AES_SBOX_INV[b] for b in row] for row in state]

def _aes_shift_rows(state: list) -> list:
    return [
        state[0],
        state[1][1:] + state[1][:1],
        state[2][2:] + state[2][:2],
        state[3][3:] + state[3][:3],
    ]

def _aes_shift_rows_inv(state: list) -> list:
    return [
        state[0],
        state[1][-1:] + state[1][:-1],
        state[2][-2:] + state[2][:-2],
        state[3][-3:] + state[3][:-3],
    ]

def _aes_mix_columns(state: list) -> list:
    result = []
    for col in range(4):
        s = [state[row][col] for row in range(4)]
        result_col = [
            _gf_mul(s[0],2)^_gf_mul(s[1],3)^s[2]^s[3],
            s[0]^_gf_mul(s[1],2)^_gf_mul(s[2],3)^s[3],
            s[0]^s[1]^_gf_mul(s[2],2)^_gf_mul(s[3],3),
            _gf_mul(s[0],3)^s[1]^s[2]^_gf_mul(s[3],2),
        ]
        for row in range(4):
            if len(result) <= row:
                result.append([])
            result[row].append(result_col[row])
    return result

def _aes_mix_columns_inv(state: list) -> list:
    result = []
    for col in range(4):
        s = [state[row][col] for row in range(4)]
        result_col = [
            _gf_mul(s[0],0xe)^_gf_mul(s[1],0xb)^_gf_mul(s[2],0xd)^_gf_mul(s[3],0x9),
            _gf_mul(s[0],0x9)^_gf_mul(s[1],0xe)^_gf_mul(s[2],0xb)^_gf_mul(s[3],0xd),
            _gf_mul(s[0],0xd)^_gf_mul(s[1],0x9)^_gf_mul(s[2],0xe)^_gf_mul(s[3],0xb),
            _gf_mul(s[0],0xb)^_gf_mul(s[1],0xd)^_gf_mul(s[2],0x9)^_gf_mul(s[3],0xe),
        ]
        for row in range(4):
            if len(result) <= row:
                result.append([])
            result[row].append(result_col[row])
    return result

def _aes_add_round_key(state: list, round_key: list) -> list:
    return [[state[row][col] ^ round_key[row][col] for col in range(4)] for row in range(4)]

def _aes_key_expansion(key: bytes) -> list:
    """Génère 11 round keys de 16 octets pour AES-128."""
    w = [list(key[i:i+4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        temp = list(w[i-1])
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]
            temp = [_AES_SBOX[b] for b in temp]
            temp[0] ^= _AES_RCON[(i//4)-1]
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    round_keys = []
    for r in range(11):
        rk = [[w[r*4+col][row] for col in range(4)] for row in range(4)]
        round_keys.append(rk)
    return round_keys

def _bytes_to_state(block: bytes) -> list:
    return [[block[row + 4*col] for col in range(4)] for row in range(4)]

def _state_to_bytes(state: list) -> bytes:
    return bytes(state[row][col] for col in range(4) for row in range(4))

def _aes_encrypt_block(block: bytes, round_keys: list) -> bytes:
    state = _bytes_to_state(block)
    state = _aes_add_round_key(state, round_keys[0])
    for r in range(1, 10):
        state = _aes_sub_bytes(state)
        state = _aes_shift_rows(state)
        state = _aes_mix_columns(state)
        state = _aes_add_round_key(state, round_keys[r])
    state = _aes_sub_bytes(state)
    state = _aes_shift_rows(state)
    state = _aes_add_round_key(state, round_keys[10])
    return _state_to_bytes(state)

def _aes_decrypt_block(block: bytes, round_keys: list) -> bytes:
    state = _bytes_to_state(block)
    state = _aes_add_round_key(state, round_keys[10])
    for r in range(9, 0, -1):
        state = _aes_shift_rows_inv(state)
        state = _aes_sub_bytes_inv(state)
        state = _aes_add_round_key(state, round_keys[r])
        state = _aes_mix_columns_inv(state)
    state = _aes_shift_rows_inv(state)
    state = _aes_sub_bytes_inv(state)
    state = _aes_add_round_key(state, round_keys[0])
    return _state_to_bytes(state)

def _aes_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Clé AES-128 : exactement 16 octets requis.")
    round_keys = _aes_key_expansion(key)
    padded     = _pkcs7_pad(plaintext, 16)
    ciphertext = b""
    prev       = iv
    for i in range(0, len(padded), 16):
        block      = _xor_bytes(padded[i:i+16], prev)
        cipher_block = _aes_encrypt_block(block, round_keys)
        ciphertext += cipher_block
        prev        = cipher_block
    return ciphertext

def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(key) != 16:
        raise ValueError("Clé AES-128 : exactement 16 octets requis.")
    round_keys = _aes_key_expansion(key)
    plaintext  = b""
    prev       = iv
    for i in range(0, len(ciphertext), 16):
        block       = ciphertext[i:i+16]
        decrypted   = _aes_decrypt_block(block, round_keys)
        plaintext  += _xor_bytes(decrypted, prev)
        prev        = block
    return _pkcs7_unpad(plaintext)


# ═══════════════════════════════════════════════════════════════════════════════
#  ChaCha20
# ═══════════════════════════════════════════════════════════════════════════════

def _chacha20_quarter_round(a, b, c, d):
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotate_left(d, 16, 32)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotate_left(b, 12, 32)
    a = (a + b) & 0xFFFFFFFF; d ^= a; d = _rotate_left(d,  8, 32)
    c = (c + d) & 0xFFFFFFFF; b ^= c; b = _rotate_left(b,  7, 32)
    return a, b, c, d

def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    """Génère un bloc de 64 octets de keystream ChaCha20."""
    constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]
    key_words  = [int.from_bytes(key[i:i+4],   "little") for i in range(0, 32, 4)]
    nonce_words= [int.from_bytes(nonce[i:i+4], "little") for i in range(0, 12, 4)]

    state = constants + key_words + [counter] + nonce_words
    working = list(state)

    for _ in range(10):  # 20 rounds = 10 double rounds
        working[0],working[4],working[8], working[12] = _chacha20_quarter_round(working[0],working[4],working[8], working[12])
        working[1],working[5],working[9], working[13] = _chacha20_quarter_round(working[1],working[5],working[9], working[13])
        working[2],working[6],working[10],working[14] = _chacha20_quarter_round(working[2],working[6],working[10],working[14])
        working[3],working[7],working[11],working[15] = _chacha20_quarter_round(working[3],working[7],working[11],working[15])
        working[0],working[5],working[10],working[15] = _chacha20_quarter_round(working[0],working[5],working[10],working[15])
        working[1],working[6],working[11],working[12] = _chacha20_quarter_round(working[1],working[6],working[11],working[12])
        working[2],working[7],working[8], working[13] = _chacha20_quarter_round(working[2],working[7],working[8], working[13])
        working[3],working[4],working[9], working[14] = _chacha20_quarter_round(working[3],working[4],working[9], working[14])

    output = [(working[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return b"".join(w.to_bytes(4, "little") for w in output)

def _chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes, counter: int = 1) -> bytes:
    """Chiffre (ou déchiffre, opération symétrique) avec ChaCha20."""
    if len(key) != 32:
        raise ValueError("Clé ChaCha20 : exactement 32 octets requis.")
    if len(nonce) != 12:
        raise ValueError("Nonce ChaCha20 : exactement 12 octets requis.")
    result = b""
    for i, block_start in enumerate(range(0, len(plaintext), 64)):
        keystream = _chacha20_block(key, counter + i, nonce)
        chunk     = plaintext[block_start:block_start+64]
        result   += _xor_bytes(keystream[:len(chunk)], chunk)
    return result


# ═══════════════════════════════════════════════════════════════════════════════
#  RSA — from scratch (génération de clés, chiffrement par blocs)
# ═══════════════════════════════════════════════════════════════════════════════

def _is_prime(n: int, k: int = 10) -> bool:
    """Test de primalité Miller-Rabin."""
    if n < 2:   return False
    if n == 2:  return True
    if n % 2 == 0: return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1; d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1): continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1: break
        else:
            return False
    return True

def _generate_prime(bits: int) -> int:
    """Génère un nombre premier de `bits` bits."""
    while True:
        n = secrets.randbits(bits) | (1 << bits - 1) | 1
        if _is_prime(n):
            return n

def _mod_inverse(a: int, m: int) -> int:
    """Algorithme d'Euclide étendu pour trouver l'inverse modulaire."""
    g, x, _ = _extended_gcd(a, m)
    if g != 1:
        raise ValueError("Inverse modulaire inexistant.")
    return x % m

def _extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = _extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def rsa_generate_keys(bits: int = 512) -> dict:
    """
    Génère une paire de clés RSA.
    Retourne {"public": (e, n), "private": (d, n)}.
    bits = 512 pour rapidité en démo (1024+ recommandé en production).
    """
    p = _generate_prime(bits // 2)
    q = _generate_prime(bits // 2)
    while q == p:
        q = _generate_prime(bits // 2)
    n   = p * q
    phi = (p - 1) * (q - 1)
    e   = 65537
    d   = _mod_inverse(e, phi)
    return {"public": (e, n), "private": (d, n)}

def _rsa_encrypt_int(m: int, e: int, n: int) -> int:
    return pow(m, e, n)

def _rsa_decrypt_int(c: int, d: int, n: int) -> int:
    return pow(c, d, n)

def rsa_encrypt(plaintext: bytes, public_key: tuple) -> bytes:
    """
    Chiffre des données avec RSA par blocs.
    Chaque bloc < n est chiffré séparément et stocké sur (key_bytes) octets.
    """
    e, n = public_key
    key_bytes  = (n.bit_length() + 7) // 8
    block_size = key_bytes - 1   # bloc plaintext < n

    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        chunk = plaintext[i:i+block_size]
        m     = _bytes_to_int(chunk)
        c     = _rsa_encrypt_int(m, e, n)
        ciphertext += c.to_bytes(key_bytes, "big")
    return ciphertext

def rsa_decrypt(ciphertext: bytes, private_key: tuple) -> bytes:
    d, n = private_key
    key_bytes  = (n.bit_length() + 7) // 8
    block_size = key_bytes - 1

    plaintext = b""
    for i in range(0, len(ciphertext), key_bytes):
        chunk = ciphertext[i:i+key_bytes]
        c     = _bytes_to_int(chunk)
        m     = _rsa_decrypt_int(c, d, n)
        # Reconstruire les octets en préservant la taille du bloc original
        decrypted = m.to_bytes(block_size, "big")
        plaintext += decrypted
    # Retirer les zéros de padding en tête du dernier bloc
    return plaintext.lstrip(b"\x00") if plaintext else plaintext


# ═══════════════════════════════════════════════════════════════════════════════
#  ElGamal — from scratch (génération de clés, chiffrement par blocs)
# ═══════════════════════════════════════════════════════════════════════════════

def elgamal_generate_keys(bits: int = 256) -> dict:
    """
    Génère une paire de clés ElGamal.
    Retourne {"public": (p, g, y), "private": (p, g, x)}.
    """
    p = _generate_prime(bits)
    g = 2  # générateur simple

    # clé privée x aléatoire dans [2, p-2]
    x = secrets.randbelow(p - 3) + 2
    y = pow(g, x, p)   # clé publique y = g^x mod p

    return {
        "public":  (p, g, y),
        "private": (p, g, x),
    }

def elgamal_encrypt(plaintext: bytes, public_key: tuple) -> bytes:
    """
    Chiffre avec ElGamal par blocs.
    Chaque bloc est encodé comme deux entiers (c1, c2) stockés ensemble.
    """
    p, g, y = public_key
    key_bytes  = (p.bit_length() + 7) // 8
    block_size = key_bytes - 1

    ciphertext = b""
    for i in range(0, len(plaintext), block_size):
        chunk = plaintext[i:i+block_size]
        m     = _bytes_to_int(chunk)
        k     = secrets.randbelow(p - 3) + 2
        c1    = pow(g, k, p)
        c2    = (m * pow(y, k, p)) % p
        # Stocker c1 et c2 sur key_bytes octets chacun
        ciphertext += c1.to_bytes(key_bytes, "big") + c2.to_bytes(key_bytes, "big")
    return ciphertext

def elgamal_decrypt(ciphertext: bytes, private_key: tuple) -> bytes:
    p, g, x = private_key
    key_bytes  = (p.bit_length() + 7) // 8
    block_size = key_bytes - 1
    pair_size  = key_bytes * 2  # c1 + c2

    plaintext = b""
    for i in range(0, len(ciphertext), pair_size):
        pair = ciphertext[i:i+pair_size]
        c1   = _bytes_to_int(pair[:key_bytes])
        c2   = _bytes_to_int(pair[key_bytes:])
        s    = pow(c1, x, p)
        s_inv = _mod_inverse(s, p)
        m    = (c2 * s_inv) % p
        plaintext += m.to_bytes(block_size, "big")
    return plaintext.lstrip(b"\x00") if plaintext else plaintext


# ═══════════════════════════════════════════════════════════════════════════════
#  HACHAGE MOT DE PASSE
# ═══════════════════════════════════════════════════════════════════════════════

def hash_password(password: str, salt: bytes) -> tuple[str, str]:
    """
    Hash un mot de passe avec SHA-256 + salt.

    Args:
        password : mot de passe en clair
        salt     : bytes aléatoires (os.urandom(32) ou secrets.token_bytes(32))

    Retourne:
        (password_hash_hex, salt_hex)  — les deux stockés en base
    """
    salted        = salt + password.encode("utf-8")
    password_hash = sha256(salted)
    salt_hex      = salt.hex()
    return password_hash, salt_hex

def verify_password(password: str, stored_hash: str, stored_salt: str) -> bool:
    """
    Vérifie qu'un mot de passe correspond au hash stocké en base.

    Args:
        password    : mot de passe saisi par l'utilisateur
        stored_hash : password_hash récupéré depuis la DB (hex)
        stored_salt : salt récupéré depuis la DB (hex)

    Retourne:
        True si le mot de passe est correct, False sinon.
    """
    salt_bytes    = bytes.fromhex(stored_salt)
    salted        = salt_bytes + password.encode("utf-8")
    computed_hash = sha256(salted)
    return computed_hash == stored_hash


# ═══════════════════════════════════════════════════════════════════════════════
#  INTÉGRITÉ FICHIER
# ═══════════════════════════════════════════════════════════════════════════════

def compute_integrity_hash(data: bytes) -> str:
    """
    Calcule le SHA-256 du contenu brut (avant chiffrement).
    Stocké en base dans Files.integrity_hash.
    """
    return sha256(data)

def verify_integrity(data: bytes, stored_hash: str) -> bool:
    """
    Vérifie l'intégrité d'un fichier déchiffré.
    Compare le hash du contenu déchiffré avec le hash stocké en base.
    Retourne True si intact, False si corrompu ou modifié.
    """
    return sha256(data) == stored_hash


# ═══════════════════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE UNIFIÉ — encrypt / decrypt
# ═══════════════════════════════════════════════════════════════════════════════

CRYPTO_MODES = {
    "1": "SHA1",
    "2": "SHA256",
    "3": "DES",
    "4": "3DES",
    "5": "AES",
    "6": "ChaCha20",
    "7": "RSA",
    "8": "ElGamal",
}

def prompt_crypto_mode() -> str:
    """
    Affiche le menu de sélection de l'algorithme et retourne la clé choisie.
    Retourne une string parmi : SHA1, SHA256, DES, 3DES, AES, ChaCha20, RSA, ElGamal.
    """
    print("\n  Choisissez l'algorithme de chiffrement :")
    for k, v in CRYPTO_MODES.items():
        print(f"    {k}. {v}")
    while True:
        choix = input("  Votre choix : ").strip()
        if choix in CRYPTO_MODES:
            return CRYPTO_MODES[choix]
        print("  Choix invalide, réessayez.")

def encrypt(data: bytes, mode: str) -> tuple[bytes, dict]:
    """
    Chiffre `data` avec l'algorithme `mode`.

    Retourne:
        (encrypted_bytes, metadata_dict)
        metadata contient tout ce qui est nécessaire au déchiffrement
        (clés, IV, nonce...) — stocké en JSON dans Files.crypto_meta.

    Note : pour SHA1 et SHA256, le "chiffrement" est en réalité un hachage
    (one-way). Ces modes sont proposés pour la démonstration pédagogique
    mais ne permettent pas de retrouver le contenu original.
    """
    mode = mode.upper()

    if mode == "SHA1":
        digest = sha1(data)
        return digest.encode(), {"mode": "SHA1"}

    elif mode == "SHA256":
        digest = sha256(data)
        return digest.encode(), {"mode": "SHA256"}

    elif mode == "DES":
        key = os.urandom(8)
        iv  = os.urandom(8)
        encrypted = _des_cfb_encrypt(data, key, iv)
        return encrypted, {"mode": "DES", "key": key.hex(), "iv": iv.hex()}

    elif mode == "3DES":
        key = os.urandom(24)
        iv  = os.urandom(8)
        encrypted = _3des_cfb_encrypt(data, key, iv)
        return encrypted, {"mode": "3DES", "key": key.hex(), "iv": iv.hex()}

    elif mode == "AES":
        key = os.urandom(16)
        iv  = os.urandom(16)
        encrypted = _aes_cbc_encrypt(data, key, iv)
        return encrypted, {"mode": "AES", "key": key.hex(), "iv": iv.hex()}

    elif mode == "CHACHA20":
        key   = os.urandom(32)
        nonce = os.urandom(12)
        encrypted = _chacha20_encrypt(data, key, nonce)
        return encrypted, {"mode": "ChaCha20", "key": key.hex(), "nonce": nonce.hex()}

    elif mode == "RSA":
        keys = rsa_generate_keys(bits=512)
        e, n = keys["public"]
        d, _ = keys["private"]
        encrypted = rsa_encrypt(data, (e, n))
        return encrypted, {
            "mode": "RSA",
            "e": str(e), "n": str(n), "d": str(d)
        }

    elif mode == "ELGAMAL":
        keys   = elgamal_generate_keys(bits=256)
        p, g, y = keys["public"]
        _, _, x = keys["private"]
        encrypted = elgamal_encrypt(data, (p, g, y))
        return encrypted, {
            "mode": "ElGamal",
            "p": str(p), "g": str(g), "y": str(y), "x": str(x)
        }

    else:
        raise ValueError(f"Algorithme inconnu : '{mode}'")


def decrypt(encrypted: bytes, metadata: dict) -> bytes:
    """
    Déchiffre `encrypted` en utilisant les informations dans `metadata`.

    Args:
        encrypted : contenu chiffré lu depuis le disque
        metadata  : dict issu de json.loads(Files.crypto_meta)

    Retourne:
        bytes du contenu original.
    """
    mode = metadata.get("mode", "").upper()

    if mode in ("SHA1", "SHA256"):
        raise ValueError(
            f"{mode} est une fonction de hachage one-way : "
            "le contenu original ne peut pas être récupéré."
        )

    elif mode == "DES":
        key = bytes.fromhex(metadata["key"])
        iv  = bytes.fromhex(metadata["iv"])
        return _des_cfb_decrypt(encrypted, key, iv)

    elif mode == "3DES":
        key = bytes.fromhex(metadata["key"])
        iv  = bytes.fromhex(metadata["iv"])
        return _3des_cfb_decrypt(encrypted, key, iv)

    elif mode == "AES":
        key = bytes.fromhex(metadata["key"])
        iv  = bytes.fromhex(metadata["iv"])
        return _aes_cbc_decrypt(encrypted, key, iv)

    elif mode == "CHACHA20":
        key   = bytes.fromhex(metadata["key"])
        nonce = bytes.fromhex(metadata["nonce"])
        return _chacha20_encrypt(encrypted, key, nonce)  # symétrique

    elif mode == "RSA":
        d = int(metadata["d"])
        n = int(metadata["n"])
        return rsa_decrypt(encrypted, (d, n))

    elif mode == "ELGAMAL":
        p = int(metadata["p"])
        g = int(metadata["g"])
        x = int(metadata["x"])
        return elgamal_decrypt(encrypted, (p, g, x))

    else:
        raise ValueError(f"Algorithme inconnu dans les métadonnées : '{mode}'")
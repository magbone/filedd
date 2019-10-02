# coding: utf-8

from Crypto.Cipher import AES
from tqdm import tqdm
import mmap
import os
import hashlib
from time import strftime


__file_header__ = b"\xf0\x66\x69\x6c\x65\x64\x64"

__crypto_methods__ = [
     "AES_ECB"
]

__hash_methods__ = [
    "sha256"
]
# +-------------+---------------+-------------+-------------+------+-------------+
# | file_header | crypto_method | create_time | hash_method | hash | padding_len |
# +-------------+---------------+-------------+-------------+------+-------------+
# file_header: start as 0xf0, followed by 'filedd'
# crypto_method: 1 byte
# create_time: ascii bytes end with \x00
# hash_method: 1 byte
# hash: value computed by hash method
# padding_len: 1byte the crypto_method padding

def file_header_create(file_in, crypto_method = 0, hash_method=0, padding=0):
    header = b""

    header += __file_header__
    header += chr(crypto_method).encode('ascii')
    header = header + strftime("%a, %d, %b %Y %H:%M:%S %z").encode('ascii') + b'\x00'
    header += chr(hash_method).encode("ascii")
    header += file_hash256(file_in, 1)
    header += chr(padding).encode('ascii')
    return header

def file_hash256(file_in, hr = 0):
    file_hash = hashlib.sha256()

    with open(file_in, 'rb') as f:
        for chunk in iter(lambda: f.read(256 * 128), b''):
            file_hash.update(chunk)
    if not hr:
        return file_hash.hexdigest()
    return file_hash.digest()

def file_encrypt(file_in, file_out, private_key):
    aes = AES.new(private_key, AES.MODE_ECB)
    file_size = os.path.getsize(file_in)
    print("File input path: %s, file size: %d" %(file_in, file_size))

    file_header = file_header_create(file_in, 0, 0, 16 - (file_size % 16))

    pos = 0
    o_index = len(file_header)
    with open(file_in, "r+b") as i_f, open(file_out, "wb+") as o_f, tqdm(total=file_size) as p_bar:
        i_mm = mmap.mmap(i_f.fileno(), 0)
        o_f.write(file_header)
        o_f.seek(o_index)
        while pos < file_size:
            i_mm.seek(pos)
            value = i_mm.read(16)

            pos += 16
            if pos <= file_size:
                o_f.write(aes.encrypt(value))

                p_bar.update(16)
            else:

                padding_len = pos - file_size
                p_bar.update(16 - padding_len)
                for i in range(0, padding_len):
                    value += b'\x00'

                o_f.write(aes.encrypt(value))

            o_index += 16
        i_mm.close()



def file_decrypt(file_in, file_out, private_key):
    aes = AES.new(private_key, AES.MODE_ECB)
    file_size = os.path.getsize(file_in)
    print("File input path: %s, file size: %d" % (file_in, file_size))

    pos = 0
    decrypted_hash = hashlib.sha256()
    with open(file_in, "r+b") as i_f, open(file_out, "wb+") as o_f, tqdm(total=file_size) as p_bar:
        i_mm = mmap.mmap(i_f.fileno(), 0)
        # check filedd header

        if i_mm.read(len(__file_header__)) != __file_header__:
            i_mm.close()
            i_f.close()
            return
        pos += len(__file_header__)

        i_mm.seek(pos)
        # Crypto method
        crypto_method = i_mm.read(1)
        pos += 1
        i_mm.seek(pos)
        time = ""
        n = i_mm.read(1)
        while n != b'\x00':
            time += str(n, encoding="utf8")
            pos += 1
            i_mm.seek(pos)
            n = i_mm.read(1)
        print("Create time: ", time)
        pos += 1
        i_mm.seek(pos)
        # Hash method
        hash_methods = i_mm.read(1)
        pos += 1
        i_mm.seek(pos)

        file_hash = i_mm.read(32)
        print("File hash:", file_hash.hex())
        pos += 32
        i_mm.seek(pos)
        # Padding
        padding_len = ord(i_mm.read(1))
        print("Padding Len:", padding_len)
        pos += 1
        i_mm.seek(pos)

        p_bar.update(pos)
        # Data block
        o_index = 0
        while pos < file_size:
            cipher_text = i_mm.read(16)
            plain_text = aes.decrypt(cipher_text)

            p_bar.update(16)

            if pos + 16 == file_size and padding_len != 0:
                plain_text = plain_text[0: 16 - padding_len]
            o_f.write(plain_text)
            decrypted_hash.update(plain_text)
            pos += 16
            o_index += 16
            i_mm.seek(pos)
            o_f.seek(o_index)

        print("After decrypted file hash:", decrypted_hash.hexdigest())

        i_mm.close()









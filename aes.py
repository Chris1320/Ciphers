#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
MIT License
Copyright (c) 2020 Chris1320

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import base64
import hashlib
from Cryptodome import Random
from Cryptodome.Cipher import AES

class AES256(object):
    """
    The class that contains methods for working with AES-256.

    Credits to the people from StackOverflow! LMAO

    https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
    """

    def __init__(self, key, encoding="utf-8"):
        """
        The initialization method of AES256() class.

        :param str key: The key/password of the message.
        """

        self.VERSION = "0.0.1.2"

        self.bs = AES.block_size  # The block size
        self.encoding = encoding  # The encoding to be used when calling `encode()` and `decode()`.
        self.key = hashlib.sha256(key.encode(self.encoding)).digest()  # The hashed key

    def encrypt(self, message):
        """
        Encrypt <message> using <self.key> as the key/password.

        :param str message: The message to encrypt.

        :returns bytes: The ciphertext.
        """

        padded_message = self._pad(message)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)

        emessage = padded_message.encode(self.encoding)  # Encoded message
        ciphertext = base64.b64encode(iv + cipher.encrypt(emessage))

        return ciphertext

    def decrypt(self, ciphertext):
        """
        Decrypt <ciphertext> using <self.key> as the key/password.

        :param bytes ciphertext: The ciphertext to decrypt.

        :returns str: The plaintext version of the ciphertext.
        """

        ciphertext = base64.b64decode(ciphertext)
        iv = ciphertext[:AES.block_size]  # Get the iv from the ciphertext
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext[AES.block_size:])
        plaintext = self._unpad(decrypted).decode(self.encoding)

        return plaintext

    def _pad(self, s):
        """
        Add a padding to <s>.
        """

        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        """
        Remove padding from <s>.
        """

        return s[:-ord(s[len(s)-1:])]
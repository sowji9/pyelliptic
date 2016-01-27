#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 Yann GUIBET <yannguibet@gmail.com>.
# All rights reserved.
#
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     1. Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#
#     2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS ``AS IS''
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
# IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from .openssl import OpenSSL


class Cipher:
    """
    Symmetric encryption

        import pyelliptic
        iv = pyelliptic.Cipher.gen_IV('aes-256-cfb')
        ctx = pyelliptic.Cipher("secretkey", iv, 1, ciphername='aes-256-cfb')
        ciphertext = ctx.update('test1')
        ciphertext += ctx.update('test2')
        ciphertext += ctx.final()

        ctx2 = pyelliptic.Cipher("secretkey", iv, 0, ciphername='aes-256-cfb')
        print ctx2.ciphering(ciphertext)
    """
    def __init__(self, key, iv, do, ciphername='aes-256-cbc', tag_len=12, iv_len=7, tag=None):
        """
        do == 1 => Encrypt; do == 0 => Decrypt
        """
        self.cipher = OpenSSL.get_cipher(ciphername)
        self.ctx = OpenSSL.EVP_CIPHER_CTX_new()
        if (do == 1 or do == 0):
            k = OpenSSL.malloc(key, len(key))
            IV = OpenSSL.malloc(iv, len(iv))
            if self.cipher == OpenSSL.get_cipher('aes-128-ccm') or \
               self.cipher == OpenSSL.get_cipher('aes-128-gcm'):
                OpenSSL.EVP_CipherInit_ex(self.ctx, self.cipher.get_pointer(), 0, 0, 0, do)
                self.tag_len = tag_len
                self.iv_len = iv_len
                if do == 0:
                    if tag is None or (tag is not None and len(tag) != tag_len):
                        raise Exception("Invalid Tag Input...")
                    else:
                        self.cipher_ctrl(tag_val=tag)
                else:
                    self.cipher_ctrl()
                OpenSSL.EVP_CipherInit_ex(self.ctx, 0, 0, k, IV, do)
            else:
                OpenSSL.EVP_CipherInit_ex(
                    self.ctx, self.cipher.get_pointer(), 0, k, IV, do)
        else:
            raise Exception("RTFM ...")


    def cipher_ctrl(self, set=1, tag_val=None):
        if set == 1:
            if tag_val is not None:
                tag = OpenSSL.malloc(tag_val, len(tag_val))
            else:
                tag = 0

            if 0 == OpenSSL.EVP_CIPHER_CTX_ctrl(self.ctx, OpenSSL.EVP_CTRL_CCM_SET_TAG, self.tag_len, tag):
                raise Exception("Failed to change Tag/Tag Len...")

            if 0 == OpenSSL.EVP_CIPHER_CTX_ctrl(self.ctx, OpenSSL.EVP_CTRL_CCM_SET_IVLEN, self.iv_len, 0):
                raise Exception("Failed to change IV Len...")
            return

        if set == 0:
            tag = OpenSSL.malloc(b"", self.tag_len)
            if not OpenSSL.EVP_CIPHER_CTX_ctrl(self.ctx, OpenSSL.EVP_CTRL_CCM_GET_TAG,
                                               self.tag_len, OpenSSL.byref(tag)):
                raise Exception("Failed to get Tag Len...")
            return tag.raw[0:self.tag_len]

    @staticmethod
    def get_all_cipher():
        """
        static method, returns all ciphers available
        """
        return OpenSSL.cipher_algo.keys()

    @staticmethod
    def get_blocksize(ciphername):
        cipher = OpenSSL.get_cipher(ciphername)
        return cipher.get_blocksize()

    @staticmethod
    def gen_IV(ciphername, iv_len=None):
        if iv_len is None:
            cipher = OpenSSL.get_cipher(ciphername)
            return OpenSSL.rand(cipher.get_blocksize())
        else:
            return OpenSSL.rand(iv_len)

    def get_tag(self):
        return self.cipher_ctrl(set=0)

    def update(self, input=None, total_len=None):
        i = OpenSSL.c_int(0)
        if input is None and total_len is not None:
            if OpenSSL.EVP_CipherUpdate(self.ctx, 0,
                                    OpenSSL.byref(i), 0, total_len) == 0:
                raise Exception("[OpenSSL] EVP_CipherUpdate FAIL ...")
            return

        if input is not None:
            buffer = OpenSSL.malloc(b"", len(input) + self.cipher.get_blocksize())
            inp = OpenSSL.malloc(input, len(input))
            out = OpenSSL.EVP_CipherUpdate(self.ctx, OpenSSL.byref(buffer),
                                        OpenSSL.byref(i), inp, len(input))
            if out == 0:
                raise Exception("[OpenSSL] EVP_CipherUpdate FAIL/Tag Verification failed ...")
            return buffer.raw[0:i.value]

        return

    def final(self):
        i = OpenSSL.c_int(0)
        buffer = OpenSSL.malloc(b"", self.cipher.get_blocksize())
        if (OpenSSL.EVP_CipherFinal_ex(self.ctx, OpenSSL.byref(buffer),
                                       OpenSSL.byref(i))) == 0:
            raise Exception("[OpenSSL] EVP_CipherFinal_ex FAIL ...")
        return buffer.raw[0:i.value]


    def ciphering(self, input, aad=None):
        """
        Do update and final in one method
        """
        if self.cipher == OpenSSL.get_cipher('aes-128-ccm') or \
               self.cipher == OpenSSL.get_cipher('aes-128-gcm'):
            if aad is not None:
                self.update(aad)
            buff = self.update(input)
            return buff
        else:
            buff = self.update(input)
            return buff + self.final()

    def __del__(self):
        OpenSSL.EVP_CIPHER_CTX_cleanup(self.ctx)
        OpenSSL.EVP_CIPHER_CTX_free(self.ctx)

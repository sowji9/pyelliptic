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

from hashlib import sha512, sha256, sha224
from binascii import hexlify, unhexlify
from .openssl import OpenSSL
from .cipher import Cipher
from .hash import hmac_sha256, equals
from .arithmetic import hash_160
from struct import pack, unpack
from math import ceil
from datetime import datetime, timedelta


class ECC:
    """
    Asymmetric encryption with Elliptic Curve Cryptography (ECC)
    ECDH, ECDSA and ECIES

        import pyelliptic

        alice = pyelliptic.ECC() # default curve: sect283r1
        bob = pyelliptic.ECC(curve='sect571r1')

        ciphertext = alice.encrypt("Hello Bob", bob.get_pubkey())
        print bob.decrypt(ciphertext)

        signature = bob.sign("Hello Alice")
        # alice's job :
        print pyelliptic.ECC(
            pubkey=bob.get_pubkey()).verify(signature, "Hello Alice")

        # ERROR !!!
        try:
            key = alice.get_ecdh_key(bob.get_pubkey())
        except: print("For ECDH key agreement,\
                      the keys must be defined on the same curve !")

        alice = pyelliptic.ECC(curve='sect571r1')
        print alice.get_ecdh_key(bob.get_pubkey()).encode('hex')
        print bob.get_ecdh_key(alice.get_pubkey()).encode('hex')

    """

    def __init__(self, pubkey=None, privkey=None, pubkey_x=None,
                 pubkey_y=None, raw_privkey=None, curve='sect283r1', hash='sha512'):
        """
        For a normal and High level use, specifie pubkey,
        privkey (if you need) and the curve
        """
        # t1 = datetime.now()
        if type(curve) == str:
            self.curve = OpenSSL.get_curve(curve)
        else:
            self.curve = curve

        if type(hash) == str:
            self.hash = globals()[hash]
        else:
            self.hash = hash

        if pubkey_x is not None and pubkey_y is not None:
            self._set_keys(pubkey_x, pubkey_y, raw_privkey)
        elif pubkey is not None:
            pubkey_x, pubkey_y = ECC._decode_pubkey(pubkey)
            if privkey is not None:
                raw_privkey = ECC._decode_privkey(privkey)
            self._set_keys(pubkey_x, pubkey_y, raw_privkey)
        else:
            self.privkey, self.pubkey_x, self.pubkey_y = self._generate()
        # t2 = datetime.now()
        # print 'Pyelliptic ECC:', (t2 - t1).microseconds

    def _set_keys(self, pubkey_x, pubkey_y, privkey):
        if self.raw_check_key(privkey, pubkey_x, pubkey_y) < 0:
            self.pubkey_x = None
            self.pubkey_y = None
            self.privkey = None
            raise Exception("Bad ECC keys ...")
        else:
            self.pubkey_x = pubkey_x
            self.pubkey_y = pubkey_y
            self.privkey = privkey

    @staticmethod
    def get_order(curve):
        try:
            if type(curve) == str:
                curve = OpenSSL.get_curve(curve)

            m = OpenSSL.BN_new()
            OpenSSL.EC_GROUP_get_order(OpenSSL.EC_GROUP_new_by_curve_name(curve), m, 0)
            m_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(m))
            OpenSSL.BN_bn2bin(m, m_bin)
            return m_bin.raw
        finally:
            OpenSSL.BN_free(m)

    @staticmethod
    def get_curves():
        """
        static method, returns the list of all the curves available
        """
        return OpenSSL.curves.keys()

    def get_curve(self):
        return OpenSSL.get_curve_by_id(self.curve)

    def get_curve_id(self):
        return self.curve

    def get_pubkey(self, _format='binary'):
        """
        High level function which returns :
        pubkeyX + pubkeyY
        """
        binary = b''.join((
            self.pubkey_x,
            self.pubkey_y
        ))

        if _format is 'binary':
            pubkey = b'' + unhexlify('04') + binary
        elif _format is 'hex':
            pubkey = b'04' + binary.encode('hex')
        else:
            raise Exception("[ECC] Unsupported pubkey output format ...")

        return pubkey

    def get_privkey(self):
        """
        High level function which returns
        privkey
        """
        return self.privkey

    @staticmethod
    def _decode_pubkey(pubkey, format='binary'):
        if format is 'binary':
            binary_key = pubkey
        elif format is 'hex':
            binary_key = unhexlify(pubkey)
        else:
            raise Exception("[ECC] Unsupported pubkey input format")

        conv_form = binary_key[0:1]
        if hexlify(conv_form) != b'04':
            raise Exception("[ECC] Unsupported pubkey point conversion form")
        i = int(len(binary_key) / 2 + 1)
        pubkey_x = binary_key[1:i]
        pubkey_y = binary_key[i:]
        return pubkey_x, pubkey_y

    @staticmethod
    def _decode_privkey(privkey):
        return privkey

    def _old_get_pubkey(self):
        """
        Old get_pubkey, keeps for compatibility issues.
        """
        return b''.join((pack('!H', self.curve),
                         pack('!H', len(self.pubkey_x)),
                         self.pubkey_x,
                         pack('!H', len(self.pubkey_y)),
                         self.pubkey_y
                         ))

    def _old_get_privkey(self):
        """
        Old get_privkey, keeps for compatibility issues.
        """
        return b''.join((pack('!H', self.curve),
                         pack('!H', len(self.privkey)),
                         self.privkey
                         ))

    @staticmethod
    def _old_decode_pubkey(pubkey):
        """
        Converts old exported pubkey to new format
        """
        i = 0
        curve = unpack('!H', pubkey[i:i + 2])[0]
        i += 2
        tmplen = unpack('!H', pubkey[i:i + 2])[0]
        i += 2
        pubkey_x = pubkey[i:i + tmplen]
        i += tmplen
        tmplen = unpack('!H', pubkey[i:i + 2])[0]
        i += 2
        pubkey_y = pubkey[i:i + tmplen]
        i += tmplen
        return curve, pubkey_x, pubkey_y, i

    @staticmethod
    def _old_decode_privkey(privkey):
        """
        Converts old exported privkey to new format
        """
        i = 0
        curve = unpack('!H', privkey[i:i + 2])[0]
        i += 2
        tmplen = unpack('!H', privkey[i:i + 2])[0]
        i += 2
        privkey = privkey[i:i + tmplen]
        i += tmplen
        return curve, privkey, i

    def _generate(self):
        try:
            pub_key_x = OpenSSL.BN_new()
            pub_key_y = OpenSSL.BN_new()

            key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_generate_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_generate_key FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ... " + OpenSSL.get_error())
            priv_key = OpenSSL.EC_KEY_get0_private_key(key)

            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_KEY_get0_public_key(key)

            if (OpenSSL.EC_POINT_get_affine_coordinates_GFp(group, pub_key,
                                                            pub_key_x,
                                                            pub_key_y, 0
                                                            )) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())

            field_size = OpenSSL.EC_GROUP_get_degree(OpenSSL.EC_KEY_get0_group(key))
            secret_len = int((field_size + 7) / 8)

            privkey = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(priv_key))
            pubkeyx = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(pub_key_x))
            pubkeyy = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(pub_key_y))
            OpenSSL.BN_bn2bin(priv_key, privkey)
            privkey = privkey.raw
            OpenSSL.BN_bn2bin(pub_key_x, pubkeyx)
            pubkeyx = pubkeyx.raw
            OpenSSL.BN_bn2bin(pub_key_y, pubkeyy)
            pubkeyy = pubkeyy.raw

            if len(pubkeyx) < secret_len:
                pubkeyx = pubkeyx.rjust(secret_len, b'\0')
            if len(pubkeyy) < secret_len:
                pubkeyy = pubkeyy.rjust(secret_len, b'\0')

            self.raw_check_key(privkey, pubkeyx, pubkeyy)

            return privkey, pubkeyx, pubkeyy

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)

    def get_ecdh_key(self, pubkey, kdf, format='binary'):
        """
        High level function. Compute public key with the local private key
        and returns a shared binary key
        """
        pubkey_x, pubkey_y = ECC._decode_pubkey(pubkey, format)
        return self.raw_get_ecdh_key(pubkey_x, pubkey_y)

    def raw_get_ecdh_key(self, pubkey_x, pubkey_y, cofactor=0):
        try:
            ecdh_keybuffer = OpenSSL.malloc(0, 32)

            other_key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if other_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            other_pub_key_x = OpenSSL.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
            other_pub_key_y = OpenSSL.BN_bin2bn(pubkey_y, len(pubkey_y), 0)

            other_group = OpenSSL.EC_KEY_get0_group(other_key)
            other_pub_key = OpenSSL.EC_POINT_new(other_group)
            if (other_pub_key == None):
                raise Exception("[OpenSSl] EC_POINT_new FAIL ... " + OpenSSL.get_error())

            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(other_group,
                                                            other_pub_key,
                                                            other_pub_key_x,
                                                            other_pub_key_y,
                                                            0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ..." + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_set_public_key(other_key, other_pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_check_key(other_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ... " + OpenSSL.get_error())

            own_key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if own_key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())
            own_priv_key = OpenSSL.BN_bin2bn(
                self.privkey, len(self.privkey), 0)

            # Cofactor Multiplication (required for ECSVDP-DHC)
            if cofactor:
                OpenSSL.EC_KEY_set_flags(own_key, OpenSSL.EC_KEY_get_flags(own_key) | OpenSSL.EC_FLAG_COFACTOR_ECDH)

            if (OpenSSL.EC_KEY_set_private_key(own_key, own_priv_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ... " + OpenSSL.get_error())

            OpenSSL.ECDH_set_method(own_key, OpenSSL.ECDH_OpenSSL())
            ecdh_keylen = OpenSSL.ECDH_compute_key(
                ecdh_keybuffer, 32, other_pub_key, own_key, 0)

            if ecdh_keylen != 32:
                raise Exception("[OpenSSL] ECDH keylen FAIL ... " + OpenSSL.get_error())

            return ecdh_keybuffer.raw

        finally:
            OpenSSL.EC_KEY_free(other_key)
            OpenSSL.BN_free(other_pub_key_x)
            OpenSSL.BN_free(other_pub_key_y)
            OpenSSL.EC_POINT_free(other_pub_key)
            OpenSSL.EC_KEY_free(own_key)
            OpenSSL.BN_free(own_priv_key)

    def check_key(self, privkey, pubkey):
        """
        Check the public key and the private key.
        The private key is optional (replace by None)
        """
        pubkey_x, pubkey_y = ECC._decode_pubkey(pubkey)
        if privkey is None:
            raw_privkey = None
        else:
            raw_privkey = ECC._decode_privkey(privkey)
        return self.raw_check_key(raw_privkey, pubkey_x, pubkey_y)

    def raw_check_key(self, privkey, pubkey_x, pubkey_y):
        curve = self.curve
        try:
            key = OpenSSL.EC_KEY_new_by_curve_name(curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())
            if privkey is not None:
                priv_key = OpenSSL.BN_bin2bn(privkey, len(privkey), 0)

            pub_key_x = OpenSSL.BN_bin2bn(pubkey_x, len(pubkey_x), 0)
            pub_key_y = OpenSSL.BN_bin2bn(pubkey_y, len(pubkey_y), 0)

            if privkey is not None:
                if (OpenSSL.EC_KEY_set_private_key(key, priv_key)) == 0:
                    raise Exception(
                        "[OpenSSL] EC_KEY_set_private_key FAIL ... " + OpenSSL.get_error())

            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_POINT_new(group)

            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, pub_key,
                                                            pub_key_x,
                                                            pub_key_y,
                                                            0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ... " + OpenSSL.get_error())
            return 0

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)
            OpenSSL.EC_POINT_free(pub_key)
            if privkey is not None:
                OpenSSL.BN_free(priv_key)

    @staticmethod
    def Bignum_modulo_add(a, b, curve):
        try:
            if type(curve) == str:
                curve = OpenSSL.get_curve(curve)

            ctx = OpenSSL.BN_CTX_new()
            a = OpenSSL.BN_bin2bn(a, len(a), 0)
            b = OpenSSL.BN_bin2bn(b, len(b), 0)
            m = OpenSSL.BN_new()
            OpenSSL.EC_GROUP_get_order(OpenSSL.EC_GROUP_new_by_curve_name(curve), m, 0)
            r = OpenSSL.BN_new()

            OpenSSL.BN_mod_add(r, a, b, m, ctx)
            r_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(r))
            OpenSSL.BN_bn2bin(r, r_bin)
            return r_bin.raw
        finally:
            OpenSSL.BN_free(a)
            OpenSSL.BN_free(b)
            OpenSSL.BN_free(m)
            OpenSSL.BN_free(r)
            OpenSSL.BN_CTX_free(ctx)

    @staticmethod
    def Bignum_modulo_mul(a, b, curve):
        try:
            if type(curve) == str:
                curve = OpenSSL.get_curve(curve)
            ctx = OpenSSL.BN_CTX_new()
            a = OpenSSL.BN_bin2bn(a, len(a), 0)
            b = OpenSSL.BN_bin2bn(b, len(b), 0)
            m = OpenSSL.BN_new()
            OpenSSL.EC_GROUP_get_order(OpenSSL.EC_GROUP_new_by_curve_name(curve), m, 0)
            r = OpenSSL.BN_new()

            OpenSSL.BN_mod_mul(r, a, b, m, ctx)
            r_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(r))
            OpenSSL.BN_bn2bin(r, r_bin)
            return r_bin.raw
        finally:
            OpenSSL.BN_free(a)
            OpenSSL.BN_free(b)
            OpenSSL.BN_free(m)
            OpenSSL.BN_free(r)
            OpenSSL.BN_CTX_free(ctx)


    @staticmethod
    def point_add(curve, p1_x, p1_y, p2_x, p2_y):
        try:
            p1_x = OpenSSL.BN_bin2bn(p1_x, len(p1_x), 0)
            p1_y = OpenSSL.BN_bin2bn(p1_y, len(p1_y), 0)
            p2_x = OpenSSL.BN_bin2bn(p2_x, len(p2_x), 0)
            p2_y = OpenSSL.BN_bin2bn(p2_y, len(p2_y), 0)
            group = OpenSSL.EC_GROUP_new_by_curve_name(OpenSSL.get_curve(curve))
            if group == 0:
                raise Exception("[OpenSSL] EC_GROUP_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            r = OpenSSL.EC_POINT_new(group)
            a = OpenSSL.EC_POINT_new(group)
            b = OpenSSL.EC_POINT_new(group)
            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, a, p1_x, p1_y, 0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ..." + OpenSSL.get_error())
            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, b, p2_x, p2_y, 0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ..." + OpenSSL.get_error())

            OpenSSL.EC_POINT_add(group, r, a, b, 0)
            x = OpenSSL.BN_new()
            y = OpenSSL.BN_new()
            if (OpenSSL.EC_POINT_get_affine_coordinates_GFp(group, r, x, y, 0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())
            x_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(x))
            y_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(y))
            OpenSSL.BN_bn2bin(x, x_bin)
            OpenSSL.BN_bn2bin(y, y_bin)
            return x_bin.raw, y_bin.raw

        finally:
        #    OpenSSL.EC_GROUP_free(group)
            OpenSSL.EC_POINT_free(r)
            OpenSSL.EC_POINT_free(a)
            OpenSSL.EC_POINT_free(b)
            OpenSSL.BN_free(p1_x)
            OpenSSL.BN_free(p1_y)
            OpenSSL.BN_free(p2_x)
            OpenSSL.BN_free(p2_y)
            OpenSSL.BN_free(x)
            OpenSSL.BN_free(y)

    @staticmethod
    def point_mul(curve, n, point_x, point_y):
        try:
            m = OpenSSL.BN_bin2bn(n, len(n), 0)

            point_x = OpenSSL.BN_bin2bn(point_x, len(point_x), 0)
            point_y = OpenSSL.BN_bin2bn(point_y, len(point_y), 0)

            group = OpenSSL.EC_GROUP_new_by_curve_name(OpenSSL.get_curve(curve))
            if group == 0:
                raise Exception("[OpenSSL] EC_GROUP_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            r = OpenSSL.EC_POINT_new(group)
            q = OpenSSL.EC_POINT_new(group)
            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, q, point_x, point_y, 0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ..." + OpenSSL.get_error())

            OpenSSL.EC_POINT_mul(group, r, 0, q, m, 0)
            x = OpenSSL.BN_new()
            y = OpenSSL.BN_new()
            if (OpenSSL.EC_POINT_get_affine_coordinates_GFp(group, r, x, y, 0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())
            x_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(x))
            y_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(y))
            OpenSSL.BN_bn2bin(x, x_bin)
            OpenSSL.BN_bn2bin(y, y_bin)
            return x_bin.raw, y_bin.raw

        finally:
        #    OpenSSL.EC_GROUP_free(group)
            OpenSSL.EC_POINT_free(r)
            OpenSSL.EC_POINT_free(q)
            OpenSSL.BN_free(point_x)
            OpenSSL.BN_free(point_y)
            OpenSSL.BN_free(m)
            OpenSSL.BN_free(x)
            OpenSSL.BN_free(y)

    @staticmethod
    def uncompress_ecpoint(curve, x, y_lsb):
        """
        Derives y coordinate of a compressed ec point using x and y_lsb
        """
        try:
            x = OpenSSL.BN_bin2bn(x, len(x), 0)
            y = OpenSSL.BN_new()

            group = OpenSSL.EC_GROUP_new_by_curve_name(OpenSSL.get_curve(curve))
            if group == 0:
                raise Exception("[OpenSSL] EC_GROUP_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            pub_key = OpenSSL.EC_POINT_new(group)
            if (OpenSSL.EC_POINT_set_compressed_coordinates_GFp(group, pub_key,
                                                                x, y_lsb, 0)) == 0:
                    raise Exception(
                        "[OpenSSL] EC_POINT_set_compressed_coordinates_GFp FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_POINT_get_affine_coordinates_GFp(group, pub_key,
                                                                x, y, 0)) == 0:
                    raise Exception(
                        "[OpenSSL] EC_POINT_get_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())

            y_bin = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(y))
            OpenSSL.BN_bn2bin(y, y_bin)

            return y_bin.raw

        finally:
            OpenSSL.EC_GROUP_free(group)
            OpenSSL.EC_POINT_free(pub_key)
            OpenSSL.BN_free(x)
            OpenSSL.BN_free(y)

    def sign(self, inputb, der=1):
        """
        Sign the input with ECDSA method and returns the signature
        """
        try:
            size = len(inputb)
            buff = OpenSSL.malloc(inputb, size)
            digest = OpenSSL.malloc(0, 64)
            md_ctx = OpenSSL.EVP_MD_CTX_create()
            dgst_len = OpenSSL.pointer(OpenSSL.c_int(0))
            siglen = OpenSSL.pointer(OpenSSL.c_int(0))
            sig = OpenSSL.malloc(0, 151)

            key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)
            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            priv_key = OpenSSL.BN_bin2bn(self.privkey, len(self.privkey), 0)
            pub_key_x = OpenSSL.BN_bin2bn(self.pubkey_x, len(self.pubkey_x), 0)
            pub_key_y = OpenSSL.BN_bin2bn(self.pubkey_y, len(self.pubkey_y), 0)

            if (OpenSSL.EC_KEY_set_private_key(key, priv_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_private_key FAIL ... " + OpenSSL.get_error())

            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_POINT_new(group)

            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, pub_key,
                                                            pub_key_x,
                                                            pub_key_y,
                                                            0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())

            if (OpenSSL.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ... " + OpenSSL.get_error())

            OpenSSL.EVP_MD_CTX_init(md_ctx)
            if self.hash == sha224:
                OpenSSL.EVP_DigestInit_ex(md_ctx, OpenSSL.EVP_sha224(), None)
            if self.hash == sha256:
                OpenSSL.EVP_DigestInit_ex(md_ctx, OpenSSL.EVP_sha256(), None)

            if (OpenSSL.EVP_DigestUpdate(md_ctx, buff, size)) == 0:
                raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ... " + OpenSSL.get_error())
            OpenSSL.EVP_DigestFinal_ex(md_ctx, digest, dgst_len)

            if der:
                OpenSSL.ECDSA_sign(0, digest, dgst_len.contents, sig, siglen, key)
                if (OpenSSL.ECDSA_verify(0, digest, dgst_len.contents, sig,
                                         siglen.contents, key)) != 1:
                    raise Exception("[OpenSSL] ECDSA_verify FAIL ... " + OpenSSL.get_error())
                return sig.raw[0:siglen.contents.value]
            else:
                ecdsa_sig = OpenSSL.ECDSA_do_sign(digest, dgst_len.contents, key)
                if (OpenSSL.ECDSA_do_verify(digest, dgst_len.contents, ecdsa_sig, key)) != 1:
                     raise Exception("[OpenSSL] ECDSA_verify FAIL ... " + OpenSSL.get_error())
                # ecdsa_sig = OpenSSL.d2i_ECDSA_SIG(None, OpenSSL.byref(OpenSSL.pointer(sig)), siglen.contents.value)
                sig = OpenSSL.cast(ecdsa_sig, OpenSSL.POINTER(OpenSSL.ECDSA_SIG))
                # print OpenSSL.BN_num_bytes(sig.contents.r), OpenSSL.BN_num_bytes(sig.contents.s)
                R = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(sig.contents.r))
                S = OpenSSL.malloc(0, OpenSSL.BN_num_bytes(sig.contents.s))
                OpenSSL.BN_bn2bin(sig.contents.r, R)
                OpenSSL.BN_bn2bin(sig.contents.s, S)
                return R.raw, S.raw

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)
            OpenSSL.BN_free(priv_key)
            OpenSSL.EC_POINT_free(pub_key)
            OpenSSL.EVP_MD_CTX_destroy(md_ctx)

    def verify(self, sig, inputb=None, input_digest=None, der=1):
        """
        Verify the signature with the input and the local public key.
        Returns a boolean
        """
        try:
            key = OpenSSL.EC_KEY_new_by_curve_name(self.curve)

            if key == 0:
                raise Exception("[OpenSSL] EC_KEY_new_by_curve_name FAIL ... " + OpenSSL.get_error())

            pub_key_x = OpenSSL.BN_bin2bn(self.pubkey_x, len(self.pubkey_x), 0)
            pub_key_y = OpenSSL.BN_bin2bn(self.pubkey_y, len(self.pubkey_y), 0)
            group = OpenSSL.EC_KEY_get0_group(key)
            pub_key = OpenSSL.EC_POINT_new(group)

            if (OpenSSL.EC_POINT_set_affine_coordinates_GFp(group, pub_key,
                                                            pub_key_x,
                                                            pub_key_y,
                                                            0)) == 0:
                raise Exception(
                    "[OpenSSL] EC_POINT_set_affine_coordinates_GFp FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_set_public_key(key, pub_key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_set_public_key FAIL ... " + OpenSSL.get_error())
            if (OpenSSL.EC_KEY_check_key(key)) == 0:
                raise Exception("[OpenSSL] EC_KEY_check_key FAIL ... " + OpenSSL.get_error())

            if input_digest is None:
                binputb = OpenSSL.malloc(inputb, len(inputb))
                digest = OpenSSL.malloc(0, 64)
                dgst_len = OpenSSL.pointer(OpenSSL.c_int(0))
                md_ctx = OpenSSL.EVP_MD_CTX_create()
                OpenSSL.EVP_MD_CTX_init(md_ctx)
                if self.hash == sha224:
                    OpenSSL.EVP_DigestInit_ex(md_ctx, OpenSSL.EVP_sha224(), None)
                if self.hash == sha256:
                    OpenSSL.EVP_DigestInit_ex(md_ctx, OpenSSL.EVP_sha256(), None)

                if (OpenSSL.EVP_DigestUpdate(md_ctx, binputb, len(inputb))) == 0:
                    raise Exception("[OpenSSL] EVP_DigestUpdate FAIL ... " + OpenSSL.get_error())

                OpenSSL.EVP_DigestFinal_ex(md_ctx, digest, dgst_len)
            else:
                digest = OpenSSL.malloc(input_digest, len(input_digest))
                dgst_len = OpenSSL.pointer(OpenSSL.c_int(len(input_digest)))

            if der:
                bsig = OpenSSL.malloc(sig, len(sig))
                ret = OpenSSL.ECDSA_verify(
                    0, digest, dgst_len.contents, bsig, len(sig), key)
            else:
                [R, S] = sig
                ecdsa_sig = OpenSSL.ECDSA_SIG()
                r = OpenSSL.BN_bin2bn(OpenSSL.malloc(R, len(R)), len(R), 0)
                s = OpenSSL.BN_bin2bn(OpenSSL.malloc(S, len(S)), len(S), 0)
                ecdsa_sig.r = OpenSSL.cast(r, OpenSSL.POINTER(OpenSSL.BignumType))
                ecdsa_sig.s = OpenSSL.cast(s, OpenSSL.POINTER(OpenSSL.BignumType))
                sig = OpenSSL.byref(ecdsa_sig)
                # bsig = OpenSSL.malloc(0, 151)
                # l = OpenSSL.i2d_ECDSA_SIG(sig, OpenSSL.byref(OpenSSL.pointer(bsig)))
                # print "bsig: ", l, bsig.raw[0:l]
                # ret = OpenSSL.ECDSA_verify(0, digest, dgst_len.contents, bsig, l, key)
                ret = OpenSSL.ECDSA_do_verify(digest, dgst_len.contents, sig, key)

            if ret == -1:
                return False  # Fail to Check
            else:
                if ret == 0:
                    return False  # Bad signature !
                if ret == 1:
                    return True  # Good

            return False

        finally:
            OpenSSL.EC_KEY_free(key)
            OpenSSL.BN_free(pub_key_x)
            OpenSSL.BN_free(pub_key_y)
            OpenSSL.EC_POINT_free(pub_key)
            if not der:
                OpenSSL.BN_free(r)
                OpenSSL.BN_free(s)
            if input_digest is None:
                OpenSSL.EVP_MD_CTX_destroy(md_ctx)

    def encrypt(self, data, pubkey, ephemcurve=None, ciphername='aes-256-cbc'):
        """
        Encrypt data with ECIES method using the public key of the recipient.
        """
        curve = OpenSSL.get_curve_by_id(self.curve)
        pubkey_x, pubkey_y = ECC._decode_pubkey(pubkey)
        return ECC.raw_encrypt(data, pubkey_x, pubkey_y, curve=curve,
                               ephemcurve=ephemcurve, ciphername=ciphername, hash=self.hash)

    @staticmethod
    def raw_encrypt(data, pubkey_x, pubkey_y, curve='sect283r1',
                    ephemcurve=None, ciphername='aes-256-cbc', hash=sha512):
        if type(hash) == str:
            hash = globals()[hash]

        if ephemcurve is None:
            ephemcurve = curve
        # print 'Ephem curve'
        ephem = ECC(curve=ephemcurve, hash=hash)

        pubkey = ephem.get_pubkey()
        if ciphername == 'stream-cipher':
            # Received Data is a Octet String
            l = len(data)/2
            #print 'data: ', data, len(data)
            key = ECC.kdf2(ephem.raw_get_ecdh_key(pubkey_x, pubkey_y, cofactor=1), l + 32, hash)
            key_e, key_m = key[:l], key[l:]
            #print 'key_e ', key_e, ', key_m ', key_mt
            ciphertext = unhexlify(format(int(data, 16) ^ int(hexlify(key_e), 16), '0'+str(len(data))+'x'))
            #print ciphertext
            mac = hmac_sha256(key_m, ciphertext, 160)
            return pubkey + ciphertext + mac
        else:
            key = sha512(ephem.raw_get_ecdh_key(pubkey_x, pubkey_y)).digest()
            key_e, key_m = key[:32], key[32:]
            iv = Cipher.gen_IV(ciphername)
            ctx = Cipher(key_e, iv, 1, ciphername)
            ciphertext = iv + pubkey + ctx.ciphering(data)
            mac = hmac_sha256(key_m, ciphertext)
            return ciphertext + mac

    def decrypt(self, data, ciphername='aes-256-cbc'):
        """
        Decrypt data with ECIES method using the local private key
        """
        if ciphername != 'stream-cipher':
            blocksize = OpenSSL.get_cipher(ciphername).get_blocksize()
            iv = data[:blocksize]
            i = blocksize
            coord_len = len(self.pubkey_x) * 2 + 1
            pubkey_x, pubkey_y = ECC._decode_pubkey(data[i:i + coord_len])
            i += coord_len
            ciphertext = data[i:len(data) - 32]
            i = len(data) - 32
            mac = data[i:]
            key = sha512(self.raw_get_ecdh_key(pubkey_x, pubkey_y)).digest()
            key_e, key_m = key[:32], key[32:]
            if not equals(hmac_sha256(key_m, data[:i]), mac):
                raise RuntimeError("Fail to verify data")
            ctx = Cipher(key_e, iv, 0, ciphername)
            return ctx.ciphering(ciphertext)
        else:
            i = 0
            coord_len = len(self.pubkey_x) * 2 + 1
            pubkey_x, pubkey_y = ECC._decode_pubkey(data[i:i + coord_len])
            i += coord_len
            ciphertext = data[i:len(data) - 20]
            i = len(data) - 20
            mac = data[i:]
            l = len(ciphertext)
            key = ECC.kdf2(self.raw_get_ecdh_key(pubkey_x, pubkey_y, cofactor=1), l + 32, self.hash)
            key_e, key_m = key[:l], key[l:]
            #print 'key_e ', key_e, ', key_m ', key_m
            #print 'ciphertext ', ciphertext
            if not equals(hmac_sha256(key_m, ciphertext, 160), mac):
                raise RuntimeError("Fail to verify data")

            return unhexlify(format(int(hexlify(ciphertext), 16) ^ int(hexlify(key_e), 16), '0'+str(2*len(ciphertext))+'x'))

    @staticmethod
    def kdf2(z, olen, hash):
        zb= bin(int(hexlify(z), 16))[2:].zfill(256)
        mb = ''
        zbits = len(zb)
        obits = 8*olen
        hbits = 256  # can change based on hash
        cthreshold = ceil(obits/float(hbits))
        counter = 1
        while counter <= cthreshold:
            cb = bin(counter)[2:].zfill(32)
            zcb = unhexlify(format(int(zb+cb, 2), '072x'))  # unhexlify('%x' % int(zb+cb, 2))
            h = hash(zcb).digest()
            hb = bin(int(hexlify(h), 16))[2:].zfill(256)
            mb += hb
            counter += 1
        #print 'mb len ', len(mb)
        kb = mb[:obits]
        k = unhexlify(format(int(kb, 2), '0'+str(obits/4)+'x'))
        # print 'k: ', k, len(k)
        return k

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

import sys
import ctypes
import ctypes.util

OpenSSL = None


class CipherName:
    def __init__(self, name, pointer, blocksize):
        self._name = name
        self._pointer = pointer
        self._blocksize = blocksize

    def __str__(self):
        return ("Cipher : %s | Blocksize : %s | Fonction pointer : %s" %
                (self._name, str(self._blocksize), str(self._pointer)))

    def get_pointer(self):
        return self._pointer()

    def get_name(self):
        return self._name

    def get_blocksize(self):
        return self._blocksize

class BignumType(ctypes.Structure):
    """The structure that's manipulated by the bn library.
    struct bignum_st {
        BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
        int top;	/* Index of last used d +1. */
        /* The next are internal book keeping for bn_expand. */
        int dmax;	/* Size of the d array. */
        int neg;	/* one if the number is negative */
        int flags;
    };
    """
    _fields_ = [
            ('d', ctypes.POINTER (ctypes.c_ulong)),
            ('top', ctypes.c_int),
            ('dmax', ctypes.c_int),
            ('neg', ctypes.c_int),
            ('flags', ctypes.c_int),
            ]

class _OpenSSL:
    """
    Wrapper for OpenSSL using ctypes
    """
    class ECDSA_SIG(ctypes.Structure):
        _fields_ = [("r", ctypes.POINTER(BignumType)),
                    ("s", ctypes.POINTER(BignumType))]

    def __init__(self, library):
        """
        Build the wrapper
        """
        self._lib = ctypes.CDLL(library)
        self.BignumType = BignumType
        self.pointer = ctypes.pointer
        self.POINTER = ctypes.POINTER
        self.cast = ctypes.cast
        self.c_char = ctypes.c_char
        self.c_char_p = ctypes.c_char_p
        self.c_int = ctypes.c_int
        self.c_long = ctypes.c_long
        self.byref = ctypes.byref
        self.create_string_buffer = ctypes.create_string_buffer

        self.ERR_error_string = self._lib.ERR_error_string
        self.ERR_error_string.restype = ctypes.c_char_p
        self.ERR_error_string.argtypes = [ctypes.c_ulong, ctypes.c_char_p]

        self.ERR_get_error = self._lib.ERR_get_error
        self.ERR_get_error.restype = ctypes.c_ulong
        self.ERR_get_error.argtypes = []

        self.BN_new = self._lib.BN_new
        self.BN_new.restype = ctypes.c_void_p
        self.BN_new.argtypes = []

        self.BN_add = self._lib.BN_add
        self.BN_add.restype = ctypes.c_int
        self.BN_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_void_p]

        self.BN_mul = self._lib.BN_mul
        self.BN_mul.restype = ctypes.c_int
        self.BN_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                ctypes.c_void_p, ctypes.c_void_p]

        self.BN_mod_add = self._lib.BN_mod_add
        self.BN_mod_add.restype = ctypes.c_int
        self.BN_mod_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        self.BN_mod_mul = self._lib.BN_mod_mul
        self.BN_mod_mul.restype = ctypes.c_int
        self.BN_mod_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]

        self.BN_free = self._lib.BN_free
        self.BN_free.restype = None
        self.BN_free.argtypes = [ctypes.c_void_p]

        self.BN_num_bits = self._lib.BN_num_bits
        self.BN_num_bits.restype = ctypes.c_int
        self.BN_num_bits.argtypes = [ctypes.c_void_p]

        self.BN_bn2bin = self._lib.BN_bn2bin
        self.BN_bn2bin.restype = ctypes.c_int
        self.BN_bn2bin.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.BN_bin2bn = self._lib.BN_bin2bn
        self.BN_bin2bn.restype = ctypes.c_void_p
        self.BN_bin2bn.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                   ctypes.c_void_p]

        self.BN_dec2bn = self._lib.BN_dec2bn
        self.BN_dec2bn.restype = ctypes.c_void_p
        self.BN_dec2bn.argtypes = [ctypes.c_void_p,
                                   ctypes.c_void_p]

        self.EC_GROUP_get_order = self._lib.EC_GROUP_get_order
        self.EC_GROUP_get_order.restype = ctypes.c_int
        self.EC_GROUP_get_order.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                            ctypes.c_void_p]

        self.EC_GROUP_get_degree = self._lib.EC_GROUP_get_degree
        self.EC_GROUP_get_degree.restype = ctypes.c_int
        self.EC_GROUP_get_degree.argtypes = [ctypes.c_void_p]

        self.EC_GROUP_new_by_curve_name = self._lib.EC_GROUP_new_by_curve_name
        self.EC_GROUP_new_by_curve_name.restype = ctypes.c_void_p
        self.EC_GROUP_new_by_curve_name.argtypes = [ctypes.c_int]

        self.EC_GROUP_free = self._lib.EC_GROUP_free
        self.EC_GROUP_free.restype = None
        self.EC_GROUP_free.argtypes = [ctypes.c_void_p]

        self.EC_KEY_free = self._lib.EC_KEY_free
        self.EC_KEY_free.restype = None
        self.EC_KEY_free.argtypes = [ctypes.c_void_p]

        self.EC_KEY_new_by_curve_name = self._lib.EC_KEY_new_by_curve_name
        self.EC_KEY_new_by_curve_name.restype = ctypes.c_void_p
        self.EC_KEY_new_by_curve_name.argtypes = [ctypes.c_int]

        self.EC_KEY_generate_key = self._lib.EC_KEY_generate_key
        self.EC_KEY_generate_key.restype = ctypes.c_int
        self.EC_KEY_generate_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_check_key = self._lib.EC_KEY_check_key
        self.EC_KEY_check_key.restype = ctypes.c_int
        self.EC_KEY_check_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_get0_private_key = self._lib.EC_KEY_get0_private_key
        self.EC_KEY_get0_private_key.restype = ctypes.c_void_p
        self.EC_KEY_get0_private_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_get0_public_key = self._lib.EC_KEY_get0_public_key
        self.EC_KEY_get0_public_key.restype = ctypes.c_void_p
        self.EC_KEY_get0_public_key.argtypes = [ctypes.c_void_p]

        self.EC_KEY_get0_group = self._lib.EC_KEY_get0_group
        self.EC_KEY_get0_group.restype = ctypes.c_void_p
        self.EC_KEY_get0_group.argtypes = [ctypes.c_void_p]

        self.EC_KEY_get_flags = self._lib.EC_KEY_get_flags
        self.EC_KEY_get_flags.restype = ctypes.c_int
        self.EC_KEY_get_flags.argtypes = [ctypes.c_void_p]

        self.EC_POINT_get_affine_coordinates_GFp = self._lib.EC_POINT_get_affine_coordinates_GFp
        self.EC_POINT_get_affine_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_get_affine_coordinates_GFp.argtypes = 5 * [ctypes.c_void_p]

        self.EC_KEY_set_private_key = self._lib.EC_KEY_set_private_key
        self.EC_KEY_set_private_key.restype = ctypes.c_int
        self.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p,
                                                ctypes.c_void_p]

        self.EC_KEY_set_public_key = self._lib.EC_KEY_set_public_key
        self.EC_KEY_set_public_key.restype = ctypes.c_int
        self.EC_KEY_set_public_key.argtypes = [ctypes.c_void_p,
                                               ctypes.c_void_p]

        self.EC_KEY_set_group = self._lib.EC_KEY_set_group
        self.EC_KEY_set_group.restype = ctypes.c_int
        self.EC_KEY_set_group.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.EC_KEY_set_flags = self._lib.EC_KEY_set_flags
        self.EC_KEY_set_flags.restype = None
        self.EC_KEY_set_flags.argtypes = [ctypes.c_void_p, ctypes.c_int]

        self.EC_FLAG_COFACTOR_ECDH = 0x1000

        self.EC_POINT_set_compressed_coordinates_GFp = self._lib.EC_POINT_set_compressed_coordinates_GFp
        self.EC_POINT_set_compressed_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_set_compressed_coordinates_GFp.argtypes = [ctypes.c_void_p,
                                                                 ctypes.c_void_p,
                                                                 ctypes.c_void_p,
                                                                 ctypes.c_int,
                                                                 ctypes.c_void_p]

        self.EC_POINT_set_affine_coordinates_GFp = self._lib.EC_POINT_set_affine_coordinates_GFp
        self.EC_POINT_set_affine_coordinates_GFp.restype = ctypes.c_int
        self.EC_POINT_set_affine_coordinates_GFp.argtypes = 5 * [ctypes.c_void_p]

        self.EC_POINT_new = self._lib.EC_POINT_new
        self.EC_POINT_new.restype = ctypes.c_void_p
        self.EC_POINT_new.argtypes = [ctypes.c_void_p]

        self.EC_POINT_free = self._lib.EC_POINT_free
        self.EC_POINT_free.restype = None
        self.EC_POINT_free.argtypes = [ctypes.c_void_p]

        self.BN_CTX_free = self._lib.BN_CTX_free
        self.BN_CTX_free.restype = None
        self.BN_CTX_free.argtypes = [ctypes.c_void_p]

        self.EC_POINT_add = self._lib.EC_POINT_add
        self.EC_POINT_add.restype = ctypes.c_int
        self.EC_POINT_add.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p]

        self.EC_POINT_mul = self._lib.EC_POINT_mul
        self.EC_POINT_mul.restype = ctypes.c_int
        self.EC_POINT_mul.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_void_p, ctypes.c_void_p]

        self.EC_KEY_set_private_key = self._lib.EC_KEY_set_private_key
        self.EC_KEY_set_private_key.restype = ctypes.c_int
        self.EC_KEY_set_private_key.argtypes = [ctypes.c_void_p,
                                                ctypes.c_void_p]

        self.ECDH_OpenSSL = self._lib.ECDH_OpenSSL
        self._lib.ECDH_OpenSSL.restype = ctypes.c_void_p
        self._lib.ECDH_OpenSSL.argtypes = []

        self.BN_CTX_new = self._lib.BN_CTX_new
        self._lib.BN_CTX_new.restype = ctypes.c_void_p
        self._lib.BN_CTX_new.argtypes = []

        self.ECDH_set_method = self._lib.ECDH_set_method
        self._lib.ECDH_set_method.restype = ctypes.c_int
        self._lib.ECDH_set_method.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.ECDH_compute_key = self._lib.ECDH_compute_key
        self.ECDH_compute_key.restype = ctypes.c_int
        self.ECDH_compute_key.argtypes = [ctypes.c_void_p,
                                          ctypes.c_int,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p]

        self.EVP_CipherInit_ex = self._lib.EVP_CipherInit_ex
        self.EVP_CipherInit_ex.restype = ctypes.c_int
        self.EVP_CipherInit_ex.argtypes = [ctypes.c_void_p,
                                           ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_CIPHER_CTX_new = self._lib.EVP_CIPHER_CTX_new
        self.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
        self.EVP_CIPHER_CTX_new.argtypes = []

        self.EVP_CIPHER_CTX_ctrl = self._lib.EVP_CIPHER_CTX_ctrl
        self.EVP_CIPHER_CTX_ctrl.restype = ctypes.c_void_p
        self.EVP_CIPHER_CTX_ctrl.argtypes = []

        self.EVP_CTRL_GCM_SET_IVLEN = 0x9
        self.EVP_CTRL_GCM_GET_TAG = 0x10
        self.EVP_CTRL_GCM_SET_TAG = 0x11

        self.EVP_CTRL_CCM_SET_IVLEN = self.EVP_CTRL_GCM_SET_IVLEN
        self.EVP_CTRL_CCM_GET_TAG = self.EVP_CTRL_GCM_GET_TAG
        self.EVP_CTRL_CCM_SET_TAG = self.EVP_CTRL_GCM_SET_TAG

        # Cipher
        self.EVP_aes_128_cfb128 = self._lib.EVP_aes_128_cfb128
        self.EVP_aes_128_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_128_cfb128.argtypes = []

        self.EVP_aes_256_cfb128 = self._lib.EVP_aes_256_cfb128
        self.EVP_aes_256_cfb128.restype = ctypes.c_void_p
        self.EVP_aes_256_cfb128.argtypes = []

        self.EVP_aes_128_cbc = self._lib.EVP_aes_128_cbc
        self.EVP_aes_128_cbc.restype = ctypes.c_void_p
        self.EVP_aes_128_cbc.argtypes = []

        self.EVP_aes_256_cbc = self._lib.EVP_aes_256_cbc
        self.EVP_aes_256_cbc.restype = ctypes.c_void_p
        self.EVP_aes_256_cbc.argtypes = []

        try:
            self.EVP_aes_128_ctr = self._lib.EVP_aes_128_ctr
        except AttributeError:
            pass
        else:
            self.EVP_aes_128_ctr.restype = ctypes.c_void_p
            self.EVP_aes_128_ctr.argtypes = []

        try:
            self.EVP_aes_128_gcm = self._lib.EVP_aes_128_gcm
        except AttributeError:
            pass
        else:
            self.EVP_aes_128_gcm.restype = ctypes.c_void_p
            self.EVP_aes_128_gcm.argtypes = []

        try:
            self.EVP_aes_128_ccm = self._lib.EVP_aes_128_ccm
        except AttributeError:
            pass
        else:
            self.EVP_aes_128_ccm.restype = ctypes.c_void_p
            self.EVP_aes_128_ccm.argtypes = []

        try:
            self.EVP_aes_256_ctr = self._lib.EVP_aes_256_ctr
        except AttributeError:
            pass
        else:
            self.EVP_aes_256_ctr.restype = ctypes.c_void_p
            self.EVP_aes_256_ctr.argtypes = []

        self.EVP_aes_128_ofb = self._lib.EVP_aes_128_ofb
        self.EVP_aes_128_ofb.restype = ctypes.c_void_p
        self.EVP_aes_128_ofb.argtypes = []

        self.EVP_aes_256_ofb = self._lib.EVP_aes_256_ofb
        self.EVP_aes_256_ofb.restype = ctypes.c_void_p
        self.EVP_aes_256_ofb.argtypes = []

        self.EVP_bf_cbc = self._lib.EVP_bf_cbc
        self.EVP_bf_cbc.restype = ctypes.c_void_p
        self.EVP_bf_cbc.argtypes = []

        self.EVP_bf_cfb64 = self._lib.EVP_bf_cfb64
        self.EVP_bf_cfb64.restype = ctypes.c_void_p
        self.EVP_bf_cfb64.argtypes = []

        self.EVP_rc4 = self._lib.EVP_rc4
        self.EVP_rc4.restype = ctypes.c_void_p
        self.EVP_rc4.argtypes = []

        self.EVP_CIPHER_CTX_cleanup = self._lib.EVP_CIPHER_CTX_cleanup
        self.EVP_CIPHER_CTX_cleanup.restype = ctypes.c_int
        self.EVP_CIPHER_CTX_cleanup.argtypes = [ctypes.c_void_p]

        self.EVP_CIPHER_CTX_free = self._lib.EVP_CIPHER_CTX_free
        self.EVP_CIPHER_CTX_free.restype = None
        self.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]

        self.EVP_CipherUpdate = self._lib.EVP_CipherUpdate
        self.EVP_CipherUpdate.restype = ctypes.c_int
        self.EVP_CipherUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_int]

        self.EVP_CipherFinal_ex = self._lib.EVP_CipherFinal_ex
        self.EVP_CipherFinal_ex.restype = ctypes.c_int
        self.EVP_CipherFinal_ex.argtypes = 3 * [ctypes.c_void_p]

        self.EVP_DigestInit = self._lib.EVP_DigestInit
        self.EVP_DigestInit.restype = ctypes.c_int
        self._lib.EVP_DigestInit.argtypes = 2 * [ctypes.c_void_p]

        self.EVP_DigestInit_ex = self._lib.EVP_DigestInit_ex
        self.EVP_DigestInit_ex.restype = ctypes.c_int
        self._lib.EVP_DigestInit_ex.argtypes = 3 * [ctypes.c_void_p]

        self.EVP_DigestUpdate = self._lib.EVP_DigestUpdate
        self.EVP_DigestUpdate.restype = ctypes.c_int
        self.EVP_DigestUpdate.argtypes = [ctypes.c_void_p,
                                          ctypes.c_void_p,
                                          ctypes.c_int]

        self.EVP_DigestFinal = self._lib.EVP_DigestFinal
        self.EVP_DigestFinal.restype = ctypes.c_int
        self.EVP_DigestFinal.argtypes = [ctypes.c_void_p,
                                         ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_DigestFinal_ex = self._lib.EVP_DigestFinal_ex
        self.EVP_DigestFinal_ex.restype = ctypes.c_int
        self.EVP_DigestFinal_ex.argtypes = [ctypes.c_void_p,
                                            ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_ecdsa = self._lib.EVP_ecdsa
        self._lib.EVP_ecdsa.restype = ctypes.c_void_p
        self._lib.EVP_ecdsa.argtypes = []

        self.ECDSA_SIG_new = self._lib.ECDSA_SIG_new
        self.ECDSA_SIG_new.restype = ctypes.c_void_p
        self.ECDSA_SIG_new.argtypes = []

        self.d2i_ECDSA_SIG = self._lib.d2i_ECDSA_SIG
        self.d2i_ECDSA_SIG.restype = ctypes.c_void_p
        self.d2i_ECDSA_SIG.argtypes = []

        self.i2d_ECDSA_SIG = self._lib.i2d_ECDSA_SIG
        self.i2d_ECDSA_SIG.restype = ctypes.c_int
        self.i2d_ECDSA_SIG.argtypes = []

        self.ECDSA_sign = self._lib.ECDSA_sign
        self.ECDSA_sign.restype = ctypes.c_int
        self.ECDSA_sign.argtypes = [ctypes.c_int,
                                    ctypes.c_void_p,
                                    ctypes.c_int,
                                    ctypes.c_void_p,
                                    ctypes.c_void_p,
                                    ctypes.c_void_p]

        self.ECDSA_do_sign = self._lib.ECDSA_do_sign
        self.ECDSA_do_sign.restype = ctypes.c_void_p
        self.ECDSA_do_sign.argtypes = [ctypes.c_void_p,
                                       ctypes.c_int,
                                       ctypes.c_void_p]

        self.ECDSA_verify = self._lib.ECDSA_verify
        self.ECDSA_verify.restype = ctypes.c_int
        self.ECDSA_verify.argtypes = [ctypes.c_int,
                                      ctypes.c_void_p,
                                      ctypes.c_int,
                                      ctypes.c_void_p,
                                      ctypes.c_int,
                                      ctypes.c_void_p]

        self.ECDSA_do_verify = self._lib.ECDSA_do_verify
        self.ECDSA_do_verify.restype = ctypes.c_void_p
        self.ECDSA_do_verify.argtypes = [ctypes.c_void_p,
                                         ctypes.c_int,
                                         ctypes.c_void_p,
                                         ctypes.c_void_p]

        self.EVP_MD_CTX_create = self._lib.EVP_MD_CTX_create
        self.EVP_MD_CTX_create.restype = ctypes.c_void_p
        self.EVP_MD_CTX_create.argtypes = []

        self.EVP_MD_CTX_init = self._lib.EVP_MD_CTX_init
        self.EVP_MD_CTX_init.restype = None
        self.EVP_MD_CTX_init.argtypes = [ctypes.c_void_p]

        self.EVP_MD_CTX_destroy = self._lib.EVP_MD_CTX_destroy
        self.EVP_MD_CTX_destroy.restype = None
        self.EVP_MD_CTX_destroy.argtypes = [ctypes.c_void_p]

        self.RAND_bytes = self._lib.RAND_bytes
        self.RAND_bytes.restype = ctypes.c_int
        self.RAND_bytes.argtypes = [ctypes.c_void_p, ctypes.c_int]

        self.EVP_sha224 = self._lib.EVP_sha224
        self.EVP_sha224.restype = ctypes.c_void_p
        self.EVP_sha224.argtypes = []

        self.EVP_sha256 = self._lib.EVP_sha256
        self.EVP_sha256.restype = ctypes.c_void_p
        self.EVP_sha256.argtypes = []

        self.i2o_ECPublicKey = self._lib.i2o_ECPublicKey
        self.i2o_ECPublicKey.restype = ctypes.c_int
        self.i2o_ECPublicKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p]

        self.EVP_sha512 = self._lib.EVP_sha512
        self.EVP_sha512.restype = ctypes.c_void_p
        self.EVP_sha512.argtypes = []

        self.HMAC = self._lib.HMAC
        self.HMAC.restype = ctypes.c_void_p
        self.HMAC.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_int,
                              ctypes.c_void_p, ctypes.c_void_p]

        try:
            self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC
        except:
            # The above is not compatible with all versions of OSX.
            self.PKCS5_PBKDF2_HMAC = self._lib.PKCS5_PBKDF2_HMAC_SHA1
        self.PKCS5_PBKDF2_HMAC.restype = ctypes.c_int
        self.PKCS5_PBKDF2_HMAC.argtypes = [ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_void_p, ctypes.c_int,
                                           ctypes.c_int, ctypes.c_void_p,
                                           ctypes.c_int, ctypes.c_void_p]

        self._set_ciphers()
        self._set_curves()

    def _set_ciphers(self):
        self.cipher_algo = {
            'aes-128-cbc': CipherName('aes-128-cbc',
                                      self.EVP_aes_128_cbc,
                                      16),
            'aes-256-cbc': CipherName('aes-256-cbc',
                                      self.EVP_aes_256_cbc,
                                      16),
            'aes-128-cfb': CipherName('aes-128-cfb',
                                      self.EVP_aes_128_cfb128,
                                      16),
            'aes-256-cfb': CipherName('aes-256-cfb',
                                      self.EVP_aes_256_cfb128,
                                      16),
            'aes-128-ofb': CipherName('aes-128-ofb',
                                      self._lib.EVP_aes_128_ofb,
                                      16),
            'aes-256-ofb': CipherName('aes-256-ofb',
                                      self._lib.EVP_aes_256_ofb,
                                      16),
            # 'aes-128-ctr': CipherName('aes-128-ctr',
            #                           self._lib.EVP_aes_128_ctr,
            #                           16),
            # 'aes-256-ctr': CipherName('aes-256-ctr',
            #                           self._lib.EVP_aes_256_ctr,
            #                           16),
            'bf-cfb': CipherName('bf-cfb',
                                 self.EVP_bf_cfb64,
                                 8),
            'bf-cbc': CipherName('bf-cbc',
                                 self.EVP_bf_cbc,
                                 8),
            'rc4': CipherName('rc4',
                              self.EVP_rc4,
                              # 128 is the initialisation size not block size
                              128),
        }

        if hasattr(self, 'EVP_aes_128_ctr'):
            self.cipher_algo['aes-128-ctr'] = CipherName(
                'aes-128-ctr',
                self._lib.EVP_aes_128_ctr,
                16
            )
        if hasattr(self, 'EVP_aes_128_ccm'):
            self.cipher_algo['aes-128-ccm'] = CipherName(
                'aes-128-ccm',
                self._lib.EVP_aes_128_ccm,
                16
            )
        if hasattr(self, 'EVP_aes_128_gcm'):
            self.cipher_algo['aes-128-gcm'] = CipherName(
                'aes-128_-cm',
                self._lib.EVP_aes_128_gcm,
                16
            )
        if hasattr(self, 'EVP_aes_256_ctr'):
            self.cipher_algo['aes-256-ctr'] = CipherName(
                'aes-256-ctr',
                self._lib.EVP_aes_256_ctr,
                16
            )

    def _set_curves(self):
        self.curves = {
            'secp112r1': 704,
            'secp112r2': 705,
            'secp128r1': 706,
            'secp128r2': 707,
            'secp160k1': 708,
            'secp160r1': 709,
            'secp160r2': 710,
            'secp192k1': 711,
            'secp224k1': 712,
            'secp224r1': 713,
            'secp256k1': 714,
            'secp384r1': 715,
            'secp521r1': 716,
            'sect113r1': 717,
            'sect113r2': 718,
            'sect131r1': 719,
            'sect131r2': 720,
            'sect163k1': 721,
            'sect163r1': 722,
            'sect163r2': 723,
            'sect193r1': 724,
            'sect193r2': 725,
            'sect233k1': 726,
            'sect233r1': 727,
            'sect239k1': 728,
            'sect283k1': 729,
            'sect283r1': 730,
            'sect409k1': 731,
            'sect409r1': 732,
            'sect571k1': 733,
            'sect571r1': 734,
            'prime256v1': 415,
        }

    def BN_num_bytes(self, x):
        """
        returns the length of a BN (OpenSSl API)
        """
        return int((self.BN_num_bits(x) + 7) / 8)

    def get_cipher(self, name):
        """
        returns the OpenSSL cipher instance
        """
        if name not in self.cipher_algo:
            raise Exception("Unknown cipher")
        return self.cipher_algo[name]

    def get_curve(self, name):
        """
        returns the id of a elliptic curve
        """
        if name not in self.curves:
            raise Exception("Unknown curve")
        return self.curves[name]

    def get_curve_by_id(self, id):
        """
        returns the name of a elliptic curve with his id
        """
        res = None
        for i in self.curves:
            if self.curves[i] == id:
                res = i
                break
        if res is None:
            raise Exception("Unknown curve")
        return res

    def rand(self, size):
        """
        OpenSSL random function
        """
        buffer = self.malloc(0, size)
        if self.RAND_bytes(buffer, size) != 1:
            raise RuntimeError("OpenSSL RAND_bytes failed")
        return buffer.raw

    def malloc(self, data, size):
        """
        returns a create_string_buffer (ctypes)
        """
        buffer = None
        if data != 0:
            if sys.version_info.major == 3 and isinstance(data, type('')):
                data = data.encode()
            buffer = self.create_string_buffer(data, size)
        else:
            buffer = self.create_string_buffer(size)
        return buffer

    def get_error(self):
        return OpenSSL.ERR_error_string(OpenSSL.ERR_get_error(), None)

libname = ctypes.util.find_library('crypto')
if libname is None:
    # For Windows ...
    libname = ctypes.util.find_library('libeay32.dll')
if libname is None:
    raise Exception("Couldn't load OpenSSL lib ...")
OpenSSL = _OpenSSL(libname)

# -*- encoding: utf-8 -*-
########################################################################
# simple_crypt.py: simple crypt function.
#
# Copyright (C) 2020 Mima Kang <mima777@pm.me>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

########################################################################
# this scrip only works with python3


import os
import hashlib
from base64 import b64encode, b64decode
from hmac import compare_digest


def derive_passhash(password, hash_name='sha512', salt=None, iterations=100000):
    '''This function returns str type password_hash.
    -> [hash_name] $ [iterations] $$ [salt] $s_k$ [derived_key] '''
    if salt is None:
        salt = os.urandom(32)
    if not isinstance(salt, bytes):
        salt = convert_to_bytes(salt, 'salt')
    if not isinstance(password, bytes):
        password = convert_to_bytes(password, 'password')
    if not isinstance(iterations, int):
        if isinstance(iterations, str) and iterations.isnumeric():
            iterations = int(iterations)
        else:
            print('iterations must be integer.')
            raise ValueError
    # derive passhash
    try:
        d_key = hashlib.pbkdf2_hmac(hash_name, password, salt, iterations)
        del password    # maybe it can help to make more secure?
    except ValueError as error:
        print('[!] Error cused %s' % error)
        # log(error)

    # put hash_name, salt, iterations and derived key together
    # and encode to base64 format.
    pre_v = '$'.join((hash_name, str(iterations))).encode('utf-8')
    end_v = b'$s_k$'.join((salt, d_key))
    total_value = b'$f_e$'.join((pre_v, end_v))

    user_hash = b64encode(total_value).decode(encoding='utf-8')
    return user_hash


def check_password(user_hash, asserted_pw):
    if not isinstance(asserted_pw, bytes):
        asserted_pw = convert_to_bytes(asserted_pw, 'password')

    user_hash = b64decode(user_hash.encode('utf-8'))

    h_i, s_k = user_hash.split(b'$f_e$')
    hash_name, iterations = h_i.decode('utf-8').split('$')
    salt, key = s_k.split(b'$s_k$')

    try:
        asserted_key = hashlib.pbkdf2_hmac(hash_name, asserted_pw,
                                           salt, int(iterations))
        del asserted_pw
    except ValueError as error:
        print('[!] Error caused %s' % error)

    return compare_digest(key, asserted_key)    # from hmac library


def convert_to_bytes(value, value_name, encoding='UTF-8'):
    if isinstance(value, str):
        value = value.encode(encoding)
    if not isinstance(value, bytes):
        raise ValueError('%s must be string or bytes' % value_name)
    return value

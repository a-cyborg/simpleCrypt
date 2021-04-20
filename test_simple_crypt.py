# -*- encoding: utf-8 -*-
import unittest
from simple_crypt import derive_passhash, check_password, convert_to_bytes

class TestSimpleCrypt(unittest.TestCase):
    def test_default(self):
        # case 1 (True) 
        user_hash = derive_passhash('secret')
        self.assertTrue(check_password(user_hash, 'secret'))

        # case 2 (False)
        user_hash = derive_passhash('secret')
        self.assertFalse(check_password(user_hash, 'notsecret'))
        
        # check if returned user_hash is string
        self.assertIsInstance(user_hash, str)

    def test_args(self):
        # case 1 (sha224)
        user_hash = derive_passhash('secret224', hash_name='sha224')
        self.assertTrue(check_password(user_hash, 'secret224'))
        
        # case 2 (sha256)
        user_hash = derive_passhash('secret256', hash_name='sha256')
        self.assertTrue(check_password(user_hash, 'secret256'))

        # case 3 (sha384)
        user_hash = derive_passhash('secret384', hash_name='sha384')
        self.assertTrue(check_password(user_hash, 'secret384'))

        # case 4 (md5)
        user_hash = derive_passhash('secretmd5', hash_name='md5')
        self.assertTrue(check_password(user_hash, 'secretmd5'))

    def test_salt_iterations(self):
        # case 1 (salt)
        user_hash = derive_passhash('secret', salt='dkfo29812snv')
        self.assertTrue(check_password(user_hash, 'secret'))

        # case 2 (iterations)
        user_hash = derive_passhash('secret', iterations=4000)
        self.assertTrue(check_password(user_hash, 'secret'))


if __name__ == '__main__':
    unittest.main()

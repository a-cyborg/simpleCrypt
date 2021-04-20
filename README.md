##### simple_crypt
derives password hash using pbkdf2 with HMAC and with SHA-512(default)     
as the hash inside HMAC.  

It returns string type hash encoded base64.

##### Example
    # import derive_passhash(), check_password() functions.
    >>> from simple_crypt import derive_passhash, check_password
    
    # generate new hash 
    >>> user_hash = derive_passhash('password')

    # compare hash
    >>> check_password(user_hash, 'password')
    True
    >>> check_password(user_hash, 'notpassword')
    False

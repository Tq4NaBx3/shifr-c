# shifr-c
Symmetric stream encryption with 'salt'.<br>
'Salt' is constantly generated, which gives good resistance.<br>
Data size doubles in binary mode.<br>
Tripled in text mode.<br>
There is no diagnosis of the wrong password.<br>
The encryption key size is 296 bits ( 45 - 50 letters ) .<br>
Or light key with 45 bits ( 6 - 8 lettters ) .<br>
The fast version on the command line written in C.<br>
Password encrypted × password = can serve as a hash function.<br>
Hash ÷ decrypt (password) == password<br>
If the decrypted hash with the password gives this password, then the password is correct.<br>
Double encryption of known data with a password can serve as a signature.<br>
For example Sha1Sum(data) * password * password = Signature<br>
If the signature decrypted twice gives the checksum, then this gives reason to trust the signed data.

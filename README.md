# pypass
Encrypt all your url passwords with one master password to a single text file you can store anywhere.

1. The 32bytes key that will be use for AES encryption is generated from the user master password with 20000 passes of PBKDF2. The SHA-512 of the username is used as a salt. 
2. HMAC of the username using the key as salt is used to validate the user-pass combination. Note that this HMAC is store on the first line of the "secret.txt" file.
3. The (website url, username, password) are than encrypted using AES in CBC mode using the 32bytes user key. They are each stored on a line on the "secret.txt" file.

There is a menu to add, retrieve, modify or delete a password.

I did this small project for fun, *DO NO TRUST ANY OF IT TO STORE IMPORTANT DATA*. 

- YOLO crypto.

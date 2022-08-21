# GogsToHashcat.py
Reformats password hashes and salts as stored by Gogs into hashcat 10900 | PBKDF2-HMAC-SHA256 format

```usage: GogsToHashcat.py [-h] [-n Iterations] [-o Output Filename] salt hash

Convert Gogs formatted hash password and salt to hashcat 10900 | PBKDF2-HMAC-SHA256 format.

positional arguments:
  salt                Salt string.
  hash                Hex formatted hash string.

optional arguments:
  -h, --help          show this help message and exit
  -n Iterations       The number of hash function iterations (default is 10000; check Gogs user.go file
                      EncodePassword function).
  -o Output Filename  Output file name.```

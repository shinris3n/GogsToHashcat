#!/usr/bin/env python3

'''
Gogs PBKDF2/SHA256 Password Hash Format Converter
Reformats password hashes and salts as stored by Gogs into hashcat 10900 | PBKDF2-HMAC-SHA256 format
Author: shinris3n 8/21/2022
'''

import argparse
import base64

argparser = argparse.ArgumentParser(description='Convert Gogs formatted hash password and salt to hashcat 10900 | PBKDF2-HMAC-SHA256 format.')
argparser.add_argument('salt', type=str, help='Salt string.')
argparser.add_argument('hash', type=str, help='Hex formatted hash string.')
argparser.add_argument('-n', type=int, default=10000, metavar='Iterations', help='The number of hash function iterations (default is 10000; check Gogs user.go file EncodePassword function).')
argparser.add_argument('-o', type=argparse.FileType('w'), metavar='Output Filename', help='Output file name.')
args = argparser.parse_args()

def convert(salt, hash):
	if args.n is not None:
		iterations = args.n
	else:
		iterations = 10000
	b64salt = base64.b64encode(salt.encode('ascii'))
	b64hash = base64.b64encode(bytearray.fromhex(hash))
	hashcat_format = 'sha256' + ':' + str(iterations) + ':' + b64salt.decode('ascii') + ':' + b64hash.decode('ascii')
	return (hashcat_format)

hashcat_hash = convert(args.salt, args.hash)
print (hashcat_hash)
if args.o is not None:
	args.o.write(hashcat_hash)
	print ('Hash file successfully written as:', (args.o).name)
	args.o.close()

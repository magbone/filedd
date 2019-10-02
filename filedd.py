# coding: utf-8


import argparse
import op

if __name__ == '__main__':
    parse = argparse.ArgumentParser(description="filedd is used to encrypt or decrypt file, generate new file.")
    parse.add_argument("-k", help="private key")
    parse.add_argument("--e", help="encrypt file", action="store_true")
    parse.add_argument("--d", help="decrypt file", action="store_true")
    parse.add_argument("-i", help="file input")
    parse.add_argument("-o", help="file output")
    args = parse.parse_args()

    if args.e:

        op.file_encrypt(args.i, args.o, args.k)
    elif args.d:
        print("Decrypt")
        op.file_decrypt(args.i, args.o, args.k)



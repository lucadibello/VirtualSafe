# author: Luca Di Bello

import os
import random
import string
import base64
import time
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

parser = argparse.ArgumentParser(
    description="This program let the user crypt/decrypt a folder using a generated 32 character long key.",
    epilog="Program created by Luca Di Bello"
)

parser.add_argument(
    '--generate-key',
    default=False,
    dest="generate_key_dest",
    metavar='<PATH>',
    type=str,
    help="Generates a new key using"
)

parser.add_argument(
    '--security-credentials','-credentials',
    default=False,
    dest="credentials",
    metavar=("<PASSWORD>","<KEY>"),
    nargs=2,
    type=str,
    help="Password and Salt strings used for generating a secure key"
)

parser.add_argument(
    '--crypt-dir',
    default=False,
    dest="crypt_dir",
    metavar=('<PATH_DIRECTORY>','<PATH_KEY>'),
    nargs=2,
    type=str,
    help="Crypt a specific directory using a key saved into a file"
)

parser.add_argument(
    '--decrypt-dir',
    default=False,
    dest="decrypt_dir",
    metavar=('<PATH_DIRECTORY>','<PATH_KEY>'),
    nargs=2,
    type=str,
    help="Decrypt a specific directory using a key saved into a file"
)

# Parse all passed parameters
args = parser.parse_args()


def main():
    if args.generate_key_dest and args.credentials:
        credentials = {
            "psw": args.credentials[0],
            "salt": args.credentials[1]
        }

        key = generate_key(credentials["psw"], 32, salt=credentials["salt"])
        export_key(args.generate_key_dest, key)

        print("Key saved in", os.path.abspath(args.generate_key_dest),"!")
    else:
        print("You have to: --generate-key <path> and --security-credentials <PASSWORD> <KEY>.")

    if args.crypt_dir:
        crypt = {
            "dir": args.crypt_dir[0],
            "key": args.crypt_dir[1]
        }

        # Crypt the passed directory
        crypt_directory(crypt["dir"], crypt["key"])

    elif args.decrypt_dir:
        decrypt = {
            "dir": args.decrypt_dir[0],
            "key": args.decrypt_dir[1]
        }

        # Crypt the passed directory
        decrypt_directory(decrypt["dir"], decrypt["key"])


# List all files of a folder
def get_files(dirPath):
    files = []

    # r=root, d=directories, f = files
    for r, d, f in os.walk(dirPath):
        for file in f:
            files.append(os.path.join(r, file))

    return files


# Read the file and gets all the bytes it contains
def get_file_data(filePath):
    with open(filePath, "rb") as handler:
        binary_data = handler.read()
        return binary_data


# Generate a random key in text format
def generate_key(password, key_length, salt=os.urandom(16)):
    password = password.encode("utf-8")  # Convert to type bytes
    salt = salt.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


# Saves a key to a specified file
def export_key(file, key):
    with open(file, "wb+") as handler:
        handler.write(key)


def crypt_data(binary_data, key_file_path):
    key_binaries = get_file_data(key_file_path)
    cipher_suite = Fernet(key_binaries)
    return cipher_suite.encrypt(binary_data)


def decrypt_data(crypted_data, key_file_path):
    key_binaries = get_file_data(key_file_path)
    cipher_suite = Fernet(key_binaries)
    return cipher_suite.decrypt(crypted_data)


def crypt_file(file, key_path):
    try:
        data = crypt_data(get_file_data(file), key_path)

        with open(file, "wb") as handler:
            handler.write(data)

        return True

    except:
        return False


def decrypt_file(file, key_path):
    try:
        data = decrypt_data(get_file_data(file), key_path)

        with open(file, "wb") as handler:
            handler.write(data)
        return True
    except:
        return False


def crypt_directory(dir_path, key_path):
    files = get_files(dir_path)
    failed_files = []

    tot_files = len(files)

    for file in files:
        # Crypt file using key
        status = crypt_file(file, key_path)

        if not status:
            failed_files.append(file)
        else:
            print("{} encrypted successfully".format(file))

    # Print stats
    print()
    print("[Encrypt status]")
    print("Total encrypted: {}/{}".format(tot_files-len(failed_files), tot_files))
    print()
    print("[Failed files]")

    for i in range(0, len(failed_files)):
        print(i+1, ") {}".format(failed_files[i]))


def decrypt_directory(dir_path, key_path):
    files = get_files(dir_path)
    failed_files = []

    tot_files = len(files)

    for file in files:
        # Crypt file using key
        status = decrypt_file(file, key_path)

        if not status:
            failed_files.append(file)
        else:
            print("{} decrypted successfully".format(file))

    # Print stats
    print()
    print("[Decrypt status]")
    print("Total decrypted: {}/{}".format(tot_files-len(failed_files), tot_files))
    print()
    print("[Failed files]")

    for i in range(0, len(failed_files)):
        print(i+1, ") {}".format(failed_files[i]))


main()
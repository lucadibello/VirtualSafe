# author: Luca Di Bello

import os
import base64
import argparse

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet, InvalidToken

parser = argparse.ArgumentParser(
    description="With this program you can easily protect your files using a 32 character length generated key to encode and decode them. This program can also encrypt and decrypt filenames.",
    epilog="Program created by Luca Di Bello"
)

parser.add_argument(
    '--generate-key',
    default=False,
    dest="generate_key_dest",
    metavar='<PATH>',
    type=str,
    help="Generates a new key in the passed path, it requires '--security-credentials' to generate correctly the key"
)

parser.add_argument(
    '--security-credentials',
    default=False,
    dest="credentials",
    metavar=("<PASSWORD>","<KEY>"),
    nargs=2,
    type=str,
    required="--generate-key",
    help="Used for specify the password and the salt strings used for the secure string generation"
)

parser.add_argument(
    '--crypt-dir',
    default=False,
    dest="crypt_dir",
    metavar=('<PATH_DIRECTORY>','<PATH_KEY>'),
    nargs=2,
    type=str,
    help="Used for crypt a specific directory using a key saved into a file"
)

parser.add_argument(
    '--decrypt-dir',
    default=False,
    dest="decrypt_dir",
    metavar=('<PATH_DIRECTORY>','<PATH_KEY>'),
    nargs=2,
    type=str,
    help="Used for decrypt a specific directory using a key saved into a file"
)

parser.add_argument(
    '--crypt-filename',
    default=False,
    dest="crypt_filename",
    action="store_true",
    help="Used for encrypt also the filenames during the crypt process"
)

parser.add_argument(
    '--decrypt-filename',
    default=False,
    dest="decrypt_filename",
    action="store_true",
    help="Used for decrypt also the filenames during the decrypt process"
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
        crypt_directory(crypt["dir"], crypt["key"], args.crypt_filename)

    elif args.decrypt_dir:
        decrypt = {
            "dir": args.decrypt_dir[0],
            "key": args.decrypt_dir[1]
        }

        # Crypt the passed directory
        decrypt_directory(decrypt["dir"], decrypt["key"], args.decrypt_filename)


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

    # If string, encode it do a byte array
    if type(salt) == str:
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


def crypt_file(file, key_path, crypt_filename = False):
    try:
        data = crypt_data(get_file_data(file), key_path)

        with open(file, "wb") as handler:
            handler.write(data)

        if crypt_filename:
            base_directory = os.path.split(file)[0]

            new_filename = crypt_data(
                os.path.basename(file).encode("utf-8"),
                key_path
            ).decode("utf-8")

            # Renames file
            os.rename(file, os.path.join(base_directory, new_filename))
        return True

    except PermissionError as a:
        print(a)
        return False


def decrypt_file(file, key_path, decrypt_filename = False):
    try:
        data = decrypt_data(get_file_data(file), key_path)

        with open(file, "wb") as handler:
            handler.write(data)

        if decrypt_filename:
            base_directory = os.path.split(file)[0]

            new_filename = decrypt_data(
                os.path.basename(file).encode("utf-8"),
                key_path
            ).decode("utf-8")

            # Renames file
            os.rename(file, os.path.join(base_directory, new_filename))
        return True
    except:
        return False


def crypt_directory(dir_path, key_path, crypt_filenames=False):
    files = get_files(dir_path)
    failed_files = []

    tot_files = len(files)

    for file in files:
        # Crypt file using key
        status = crypt_file(file, key_path, crypt_filenames)

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


def decrypt_directory(dir_path, key_path, crypt_filenames=False):
    files = get_files(dir_path)
    failed_files = []

    tot_files = len(files)

    for file in files:
        # Crypt file using key
        status = decrypt_file(file, key_path, crypt_filenames)

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

# VirtualSafe

With this program you can easily protect your files using a 32 character length generated key to encode and decode them. This program can also encrypt and decrypt filenames.

## Getting Started

This programs let the user generate a 32 character length string, used later for encrypt and decrypt file(s). The user can generate the password using "--generate-key <key_path> --security-credentials <key_password> <key_salt>" options.

Example of key generation:
``` shell
python virtualsafe.py --generate-key "C:\Users\luca6\Desktop\super-secure-key.txt" --security-credentials "password" "salt"
```

After the user generated his key he can already crypt his files using "--crypt-dir <directory_path> <key_path>" option.

Example of directory encrypt using generated key:
``` shell
python virtualsafe.py --crypt-dir "C:\Users\luca6\Desktop\private" "C:\Users\luca6\Desktop\super-secure-key.txt"
``` 

The command for decrypt the encrypted directory has the same structure, it just uses another option name: "--decrypt-dir <directory_path> <key_path>"

## Getting Started
FINISH THIS TOMORROW :)

### Setup

For an easy setup you can use `setup.py` file in this way:

``` shell
python .\setup.py install
```

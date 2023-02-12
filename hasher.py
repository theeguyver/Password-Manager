import base64
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import getpass


# OPERATION FUNCTIONS

def encrypt_data(input, hashed_pass):
    message = input.encode()
    f = Fernet(hashed_pass)
    encrypted = f.encrypt(message)
    return encrypted


def decrypt_data(input, hashed_pass):
    f = Fernet(hashed_pass)
    decrypted = f.decrypt(input)
    return decrypted


def file_setup():
    with open("SALT.txt", "rb") as readfile:
        content1 = readfile.read()
        readfile.close()
    con_salt = content1

    with open("VERIFIER.txt", "rb") as readfile:
        content2 = readfile.read()
        readfile.close()
    con_verifier = content2

    with open("db.txt", "rb") as readfile:
        content3 = readfile.read()
        readfile.close()
    database = content3

    return con_salt, con_verifier, database


def verify_password(password_provided, con_salt, con_verifier):
    verifier = con_verifier

    # Hash password for later comparison
    password = password_provided.encode()  # Convert to type bytes
    salt = con_salt
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    hashed_entered_pass = base64.urlsafe_b64encode(
        kdf.derive(password)
    )  # Can only use kdf once

    try:
        pass_verifier = decrypt_data(verifier, hashed_entered_pass)
        if pass_verifier == b"entered_master_correct":
            return hashed_entered_pass
    except:
        return False


def vault_setup():
    print("----------------------------------------------------------------------")
    print("                     Welcome to VAULT SETUP WIZARD                    ")
    print("----------------------------------------------------------------------")
    print()
    password_provided = getpass.getpass("Enter New Master Password: ")
    password = password_provided.encode()  # Convert to type bytes
    salt = os.urandom(32)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2 ** 14,
        r=8,
        p=1,
    )
    hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once

    file = open("SALT.txt", "wb")
    file.write(salt)
    file.close()
    del salt

    file = open("VERIFIER.txt", "wb")
    file.write(encrypt_data("entered_master_correct", hashed_entered_pass))
    file.close()

    file = open("db.txt", "w+")
    file.write(str(encrypt_data("{}", hashed_entered_pass).decode('utf-8')))
    file.close()
    del hashed_entered_pass

    input("Password Vault set up successfully. Press ENTER to continue.")

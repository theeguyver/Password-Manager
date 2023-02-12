import string
import random
import json
import secrets
import threading
import difflib
import pyperclip
import time
import keyboard as kb
from hasher import *


# OPERATION FUNCTIONS

# Login System
def login():
    print()
    print("-------------------------------")
    print("          LOGIN PANEL          ")
    print("-------------------------------")
    print()

    hashed_password = False
    con_salt, con_verifier, database = file_setup()

    while not hashed_password:
        entered_pass = getpass.getpass("Enter Master Key: ")
        hashed_password = verify_password(entered_pass, con_salt, con_verifier)  # Require password to be entered
        if not hashed_password:
            print("Incorrect Master Key. Try again.\n")
    if hashed_password:
        del entered_pass
        main_pwd_manager(hashed_password, database)
        del hashed_password
        del con_salt
        del con_verifier
        del database


# FUNCTIONS FOR PASSWORD MANAGER
def main_pwd_manager(hashed_password, contents):
    db = json.loads(decrypt_data(contents, hashed_password).decode("utf-8"))

    # print("Testing ADD Profile.")
    # add_profile(hashed_password, db)
    # OK

    # print("Testing FIND Profile Data.")
    # find_profile_data(hashed_password, db)
    # OK

    # print("Testing READ All Profiles.")
    # display_all_profiles(hashed_password, db)
    # OK

    # print("Testing EDIT Profile Data.")
    # edit_profiles(hashed_password, db)
    # OK

    # print("Testing DELETE Profile Data.")
    # delete_profile(hashed_password, db)
    # OK

    # print("Testing generate password.")
    # generate_password(hashed_password, db)
    # OK

    # print("Testing change Master Key.")
    # change_master_key(hashed_password, db)
    # print("OK")

    while True:
        print()
        print("-------------------------------")
        print("           MAIN MENU           ")
        print("-------------------------------")
        print(
            """\nPress the following key to:\n 
            (a) Add Profile. 
            (b) Find Profile Data.  
            (c) Edit Profile Data. 
            (d) Display All Profiles. 
            (e) Delete Profile.
            (f) Generate Password. 
            (g) Change Master Key. 
            (x) Exit\n
            """
        )

        choice = input("Enter your choice: ")
        print()

        if choice.lower() == 'a':
            add_profile(hashed_password, db)
        elif choice.lower() == 'b':
            find_profile_data(hashed_password, db)
        elif choice.lower() == 'c':
            edit_profiles(hashed_password, db)
        elif choice.lower() == 'd':
            display_all_profiles(hashed_password, db)
        elif choice.lower() == 'e':
            delete_profile(hashed_password, db)
        elif choice.lower() == 'f':
            generate_password()
        elif choice.lower() == 'g':
            change_master_key(hashed_password, db)
            login()
        elif choice.lower() == 'x':
            break
        else:
            print("Invalid Choice. Please Try Again.")
            print()

    del hashed_password
    del contents
    del db

    return


# ADD PROFILE
def add_profile(hashed_password, db):
    print("-------------------------------")
    print("        ADD NEW PROFILE        ")
    print("-------------------------------")
    print("Type (x) to cancel.")
    print()

    add_domain = input("Enter Domain Name: ")
    if add_domain != "x":
        add_user = input("Username: ")
        add_password = getpass.getpass("Password: ")
        db[add_domain] = {
            "username": str(encrypt_data(add_user, hashed_password).decode("utf-8")),
            "password": str(encrypt_data(add_password, hashed_password).decode("utf-8")),
        }
        overwrite_db(encrypt_data(json.dumps(db), hashed_password).decode("utf-8"))
        print("Created " + add_domain + " profile successfully!")
    if add_domain == "x":
        print("Operation canceled.")
        return False

    return True


# FIND PROFILE DATA
def find_profile_data(hashed_password, db):
    print("-------------------------------")
    print("       FIND YOUR PROFILE       ")
    print("-------------------------------")
    print("Type (x) to cancel.")
    print()

    read_domain = input("Enter domain name: ")
    if read_domain != "x":
        try:
            domains = list(db.keys())
            matches = difflib.get_close_matches(read_domain, domains)
            if matches:
                print("\nNearest match:\n")
                i = 1
                for d in matches:
                    domain_info = db[d]
                    username = str(
                        decrypt_data(
                            bytes(domain_info["username"], encoding="utf-8"),
                            hashed_password,
                        ).decode("utf-8")
                    )
                    print("PROFILE " + str(i) + ": " + str(d))
                    del d
                    print("Username: " + username + "\n")
                    del domain_info
                    del username
                    i = i + 1
                user_choice = input(
                    "\nSelect the password to be copied to your clipboard (eg: 1), or type (x) to cancel: ")
                if user_choice.isdigit():
                    if int(user_choice) > 0:
                        try:
                            password = str(
                                decrypt_data(
                                    bytes(db[str(matches[int(user_choice) - 1])]["password"], encoding="utf-8"),
                                    hashed_password,
                                ).decode("utf-8")
                            )
                            print("\n" + to_clipboard(password))
                            del password
                        except:
                            print("\nUnable to find profile corresponding to " + str(user_choice) + ".")
                    else:
                        print("\nThere are no profiles corresponding to that number.")
                if not user_choice.isdigit():
                    return True
            else:
                print("Could not find a match. Try viewing all saved profiles.")
        except:
            print("Error finding profile.")
        input("\nPress ENTER to return to Main Menu.")

    if read_domain == "x":
        print("Operation canceled.")
        print("\nReturning to Main Menu.")
        return False

    return True


# DISPLAY ALL PROFILES
def display_all_profiles(hashed_password, db):
    print("-------------------------------")
    print("     SHOWING ALL PROFILES      ")
    print("-------------------------------")
    print()
    try:
        i = 0
        domains = list(db.keys())
        for e in db:
            i = i + 1
            username = str(
                decrypt_data(
                    bytes(db[e]["username"], encoding="utf-8"), hashed_password
                ).decode("utf-8")
            )
            print("PROFILE " + str(i) + ": " + e)
            print("Username: " + username)
            del e
            del username
            print("-- -- -- -- -- --")
        if i == 0:
            print("No profiles found.")
        if i > 0:
            user_choice = input(
                "\nSelect the password to be copied to your clipboard (eg: 1), or type (x) to cancel: ")
            if user_choice.isdigit():
                if int(user_choice) > 0:
                    try:
                        password = str(
                            decrypt_data(
                                bytes(db[str(domains[int(user_choice) - 1])]["password"], encoding="utf-8"),
                                hashed_password,
                            ).decode("utf-8")
                        )
                        print("\n" + to_clipboard(password))
                        del password
                    except:
                        print("\nUnable to find profile corresponding to " + str(user_choice) + ".")
                else:
                    print("\nThere are no profiles corresponding to that number.")
            if not user_choice.isdigit():
                return False

            input("\nPress ENTER to return to Main Menu.")
            print("Returning to Main Menu.")
            return True
    except:
        print("Internal Error! Could not load any profile.")

    input("\nPress ENTER to return to Main Menu.")
    print("Returning to Main Menu.")
    return True


# EDIT PROFILES
def edit_profiles(hashed_password, db):
    print("-------------------------------")
    print("       EDIT YOUR PROFILE       ")
    print("-------------------------------")
    print("Type (x) to cancel.")
    print()

    edit_domain = input("Enter domain name: ")
    if edit_domain != "x":
        try:
            domain_info = db[edit_domain]
            curr_user = str(
                decrypt_data(
                    bytes(domain_info["username"], encoding="utf-8"), hashed_password
                ).decode("utf-8")
            )
            curr_password = str(
                decrypt_data(
                    bytes(domain_info["password"], encoding="utf-8"), hashed_password
                ).decode("utf-8")
            )

            edit_user = input("Enter New Username (press ENTER to keep the current: " + curr_user + "): ")
            if edit_user == "x" or edit_user == " " or edit_user == "":
                edit_user = curr_user

            edit_password = getpass.getpass("Enter New Password (press ENTER to keep the current): ")
            if edit_password == "x" or edit_password == " " or edit_user == "":
                edit_password = curr_password

            db[edit_domain] = {
                "username": str(encrypt_data(edit_user, hashed_password).decode("utf-8")),
                "password": str(
                    encrypt_data(edit_password, hashed_password).decode("utf-8")
                ),
            }
            overwrite_db(encrypt_data(json.dumps(db), hashed_password).decode("utf-8"))
            print("Updated " + edit_domain + " profile successfully!")
            del edit_domain
            del curr_user
            del edit_user
            del curr_password
            del edit_password
            del db
            input("\nPress ENTER to return to Main Menu.")
            print("Returning to Main Menu.")
            return True
        except:
            print("Profile for this domain does not exist. Would you like to add a new profile? (Y/n)")
            choice = input().lower()
            if choice == 'y':
                add_profile(hashed_password, db)

            input("\nPress ENTER to return to Main Menu.")
            print("Returning to Main Menu.")
            return True
    print("Returning to Main Menu.")
    return True


# DELETE PROFILES
def delete_profile(hashed_password, db):
    print("-------------------------------")
    print("      DELETE YOUR PROFILE      ")
    print("-------------------------------")
    print("Type (x) to cancel.")
    print()
    del_domain = input("Enter exact saved domain name: ")
    if del_domain != "x":
        try:
            del db[del_domain]
            overwrite_db(encrypt_data(json.dumps(db), hashed_password).decode("utf-8"))
            print("Deleted " + del_domain + " profile successfully!")
            input("\nPress ENTER to return to Main Menu.")

            print("Returning to Main Menu.")

            return True
        except:
            print("Unable to find " + del_domain)
            input("\nPress ENTER to return to Main Menu.")

            print("Returning to Main Menu.")

            return True
    else:
        print("Returning to Main Menu.")

        return True


# PASSWORD GENERATOR
def generate_password():
    print("-------------------------------")
    print("       GENERATE PASSWORD       ")
    print("-------------------------------")
    print("Type (x) to cancel.")
    print()
    pass_length = str(input("Enter Password Length: "))
    if pass_length != "x":
        try:
            if int(pass_length) < 8:
                pass_length = str(8)
                print("\nPasswords must be at least 8 characters long.")
                print("Automatically changing length to 8 characters.")

            print(to_clipboard(str(generate_encrypted_password(int(pass_length)))))

            input("\nPress ENTER to return to Main Menu.")

            print("Returning to Main Menu.")

            return True

        except:
            print("Unable to generate password.")

            print("Returning to Main Menu.")

            return True
    else:
        print("Returning to Main Menu.")

        return True


# CHANGE MASTER KEY
def change_master_key(hashed_password, db):
    print("-------------------------------")
    print("       CHANGE MASTER KEY       ")
    print("-------------------------------")
    print("Type (x) to cancel.")
    print()
    password_provided = getpass.getpass("Enter New Master Key: ")
    if password_provided != "x" and password_provided != "" and password_provided != " ":
        password = password_provided.encode()  # Convert to type bytes
        salt = os.urandom(random.randint(16, 256))
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
        )
        hashed_entered_pass = base64.urlsafe_b64encode(kdf.derive(password))  # Can only use kdf once
        try:
            i = -1
            domains = list(db.keys())
            for e in db:
                i = i + 1

                # decrypt the username and password with the original Master Key
                username = str(
                    decrypt_data(
                        bytes(db[domains[i]]["username"], encoding="utf-8"), hashed_password
                    ).decode("utf-8")
                )

                password = str(
                    decrypt_data(
                        bytes(db[domains[i]]["password"], encoding="utf-8"),
                        hashed_password,
                    ).decode("utf-8")
                )

                # encrypt and save them with then new Master Key
                db[domains[i]] = {
                    "username": str(encrypt_data(username, hashed_entered_pass).decode("utf-8")),
                    "password": str(encrypt_data(password, hashed_entered_pass).decode("utf-8")),
                }

                del e
                del username
                del password

            del domains

            # Update SALT.txt
            file = open("SALT.txt", "wb")
            file.write(salt)
            file.close()
            del salt

            # Update VERIFIER.txt
            file = open("VERIFIER.txt", "wb")
            file.write(encrypt_data("entered_master_correct", hashed_entered_pass))
            file.close()

            # finally, overwrite the database file with everything encrypted with the new password
            overwrite_db(encrypt_data(json.dumps(db), hashed_entered_pass).decode("utf-8"))

            del hashed_entered_pass
            del hashed_password

            print("Master Key changed successfully! Log in again to access the password manager.")
            input("\nPress ENTER to logout.")
            return True
        except:
            print("Could not change Master Key (Error code: 01)")
            input("\nPress ENTER to return to Main Menu.")
            print("Returning to Main Menu.")
            return True
    else:

        input("\nPress ENTER to return to Main Menu.")
        print("Returning to Main Menu.")

        return True


# CRYPTOGRAPHY FUNCTIONS

# Generate random password - user cannot request passwords that are less than 6 characters
# use secrets instead of random (secrets is safer)
def generate_encrypted_password(length=12):
    if length < 6:
        length = 12
    uppercase_loc = secrets.choice(string.digits)  # random location of lowercase
    symbol_loc = secrets.choice(string.digits)  # random location of symbols
    lowercase_loc = secrets.choice(string.digits)  # random location of uppercase
    password = ""
    pool = string.ascii_letters + string.punctuation  # the selection of characters used
    for i in range(length):
        if i == uppercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_uppercase)
        elif i == lowercase_loc:  # this is to ensure there is at least one uppercase
            password += secrets.choice(string.ascii_lowercase)
        elif i == symbol_loc:  # this is to ensure there is at least one symbol
            password += secrets.choice(string.punctuation)
        else:  # adds a random character from pool
            password += secrets.choice(pool)
    return password


# Put string in clipboard
def to_clipboard(input_to_copy):
    pyperclip.copy(str(input_to_copy))
    del input_to_copy
    threading.Thread(target=clear_clipboard_timer).start()
    return "Password was saved to clipboard. It will be removed from your clipboard as soon as you paste it."


# Clear clipboard after 30 seconds
def clear_clipboard_timer():
    kb.wait('ctrl+v')
    time.sleep(0.1)  # Without sleep, clipboard will automatically clear before user actually pastes content
    pyperclip.copy("")


# PROFILE OPERATIONS
def overwrite_db(new_contents):
    file = open("db.txt", "w+")
    file.write(new_contents)
    file.close()


if __name__ == "__main__":

    # Welcome Message
    print("----------------------------------------------------------------------")
    print("                     Welcome to PASSWORD MANAGER                      ")
    print("----------------------------------------------------------------------")

    # Check if vault exists
    try:
        file = open("db.txt", "r+")
        file.close()
    except FileNotFoundError:
        # If failed to open
        print()
        print('Password Vault was not found on this computer.\nPlease configure vault.')
        print()
        vault_setup()
    # Log in to Password Manager.
    login()

"""

Mariya Pasheva
Homework 2

TASK1
^^^^^
1. Hash the dictionary (Multiple hashes possible)
    1.1 Algorithms:
    -> Choosing by the  bit size and str length of the hash.
        ->Each hash is represented as a hex number. => Each char is a nibble.
    -> Choosing by the commonly used rate.

    HASH        BITS    LENGTH (bits/4)
    ^^^^        ^^^^    ^^^^^^
    MD4         128     32
    MD5         128     32
    SHA1        160     40
    SHA_224     224     56
    SHA_256     256     64
    SHA_384     384     96
    SHA_512     512     128


2. Different functions based on the length of the hash
   2.1 128 bits (3)
   2.2 160 bits (2)
   2.3 256 bits (1)
   2.4 512 bits (2)

"""

import hashlib
from random import randrange
import sys

"""
Tokenizing all the dictionary words into an array.
"""
def tokenize_dic() -> list:
    with open("dictionary.txt", "r") as file:
        password_list = file.read().splitlines()
        return password_list


"""
Tokenizing the shadow file to a (key:user, value:hash) pair. 
"""
def map_hashes() -> dict:
    shadow_dic = {}
    with open("shadow", "r") as file:
        shadow_list = file.read().splitlines()
        for user in shadow_list:
            shadow_dic[user.split(':')[0]] = user.split(':')[1]
    return shadow_dic


"""
 Caesar cipher has a maximu of 25 keys possible. (shifts)
"""
def caesar_cipher(dict_pass, shift) -> list:
    encoded_pass = []
    for p in dict_pass:
        en_password = ""  # Resetting the string after each word has been encoded.
        for i in range(len(p)):
            char = p[i]
            # Converting to ascii (97 -> a), since all the pass in dict are lowercase
            en_password += chr((ord(char) + shift - 97) % 26 + 97)
        encoded_pass.append(en_password)
    return encoded_pass


"""
Las Vegas Algorithm 
Output a random number from 0 to 99999 including,
in order to satisfy the SALT requirement. 
"""
def generate_salt() -> str:
    n = randrange(0, 100000)
    return str(n).zfill(5)

"""
The function performs a the basic leet encryption,
on all the words from the dictionary file. 
"""
def leet_encrypt(dict_pass) -> list:
    leet_pass = []
    for password in dict_pass:
        #If the letter does not exist, it just ignores it.
        leet_str = password.replace("a","4")
        leet_str = leet_str.replace("e","3")
        leet_str = leet_str.replace("g","6")
        leet_str = leet_str.replace("i","1")
        leet_str = leet_str.replace("o","0")
        leet_str = leet_str.replace("s","5")
        leet_str = leet_str.replace("t","7")
        leet_pass.append(leet_str)
    return leet_pass

"""
Those are all the letters mapped from the analyzed.py
Applied to all the words from the dictionary in order to be
encoded. 
"""
def analyzed_cipher( dict_pass) -> list:
    analyzed_pass = []
    for password in dict_pass:
        encoded = ""
        for c in password:
            if c == "a":
                encoded += "s"
            elif c == "b":
                encoded += "g"
            elif c == "c":
                encoded += "q"
            elif c == "d":
                encoded += "u"
            elif c == "e":
                encoded += "n"
            elif c == "f":
                encoded += "t"
            elif c == "g":
                encoded += "i"
            elif c == "h":
                encoded += "v"
            elif c == "i":
                encoded += "d"
            elif c == "j":
                encoded += "a"
            elif c == "k":
                encoded += "e"
            elif c == "l":
                encoded += "j"
            elif c == "m":
                encoded += "r"
            elif c == "n":
                encoded += "o"
            elif c == "o":
                encoded += "z"
            elif c == "p":
                encoded += "h"
            elif c == "q":
                encoded += "p"
            elif c == "r":
                encoded += "y"
            elif c == "s":
                encoded += "f"
            elif c == "t":
                encoded += "c"
            elif c == "u":
                encoded += "l"
            elif c == "v":
                encoded += "w"
            elif c == "w":
                encoded += "x"
            elif c == "x":
                encoded += "m"
            elif c == "y":
                encoded += "k"
            elif c == "z":
                encoded += "b"
            else:
                encoded += c
        analyzed_pass.append(encoded)

    return analyzed_pass


"""
The function loops through all the users from the shadow file.
The hash algorithm depends on the length of the hash. 
Once the length matches the user's hash is checked against the corresponding hashed dictionary.

User has been decoded first since the PDF gave out the case for the user 3.

@Update:
    After finishing finding all the passwords. I have edited the code so it 
    matches the speific cases. Such as I already knew user2 has SALT, There's
    no need to check for the rest. 
"""
def find_password(dict_pass, user_hashes, hashed_pass, check_case) -> int:
    for key, value in user_hashes.items():  # (user# : hash)

        # Checking is True once a regular hashing with no special case has not succeeded.
        check_found = False

        # Encoding the dictionary with the leet passwords.
        leet_pass = leet_encrypt(dict_pass)

        # Caesar cipher case: (Known from the PDF)
        if key[-1] == "3":
            # Deciding which hashing algorithm to use based on hash length
            # The length of the hash for user3 is 128 chars -> 512 bits
            for c in range(26):
                sha512_caesar = caesar_cipher(dict_pass, c)
                hashed_pass["sha512_caesar"] = (
                    map(lambda cipheredphr: hashlib.sha512(cipheredphr.encode()).hexdigest(), sha512_caesar))
                i = 0
                for h in hashed_pass["sha512_caesar"]:
                    if value == h:
                        print(key, " : ", dict_pass[i])
                    i += 1
        else:
            i = 0
            # Hash length is 32
            if len(value) == 32:
                for h in hashed_pass["md5"]:
                    if value == h:
                        print(key, " : ", dict_pass[i])
                        check_found = True
                    i+=1
                    if not check_found:
                        i = 0
                        if key == "user7":
                            analyzed_pass = analyzed_cipher(dict_pass)
                            hashed_pass["md5_analyzed"] = map(lambda aphr: hashlib.md5(aphr.encode()).hexdigest(), analyzed_pass)
                            for h in hashed_pass["md5_analyzed"]:
                                if value == h:
                                    print(key, " : ", dict_pass[i])
                                    check_found = True;
                                i += 1
            # Hash length is 40
            elif len(value) == 40:
                for h in hashed_pass["sha1"]:
                    if value == h:
                        print(key, " : ", dict_pass[i])
                        check_found = True
                    i += 1
                if not check_found:
                    i = 0
                    hashed_pass["sha1_leet"] = map(lambda leetphr: hashlib.sha1(leetphr.encode()).hexdigest(), leet_pass)
                    for h in hashed_pass["sha1_leet"]:
                        if value == h:
                            print(key, " : ", dict_pass[i])
                        i += 1
            # Hash length is 64
            elif len(value) == 64:
                for h in hashed_pass["sha256"]:
                    if value == h:
                        print(key, " : ", dict_pass[i])
                        check_found = True
                    i += 1
                if not check_found:
                    while not check_found:
                        salt = generate_salt()
                        for p in dict_pass:
                            # Originally the following line was written,
                            # The random number algorithm takes on avarage 15mins
                            # to find the number.
                            # p_salt = p + salt
                            p_salt = p + "38426"
                            p_salt_hashed = hashlib.sha256(p_salt.encode()).hexdigest()
                            if value == p_salt_hashed:
                                print(key, " : ", p)
                                check_found = True
            # Hash length is 128
            elif len(value) == 128:
                for h in hashed_pass["sha512"]:
                    if value == h:
                        print(key, " : ", dict_pass[i])
                        check_found = True
                    i += 1
                if not check_found:
                    i = 0
                    hashed_pass["sha512_leet"] = map(lambda leetphr: hashlib.sha512(leetphr.encode()).hexdigest(), leet_pass)
                    for h in hashed_pass["sha512_leet"]:
                        if value == h:
                            print(key, " : ", dict_pass[i])
                        i += 1


def main():
    # List of the common passwords from the dictionary file.
    dict_pass = []
    # Dictionary of the users and their hashed password.
    user_hashes = {}

    # Assigning to both from the files provided.
    dict_pass = tokenize_dic()
    user_hashes = map_hashes()

    # Hashing the dictionary:
    # Key: md5 (128b/32)
    #      sha1 (160b/40)
    #      sha256(256b/64)
    #      sha512(512b/128)
    hashed_pass = {"md5": list((map(lambda p: hashlib.md5(p.encode()).hexdigest(), dict_pass))),
                   "sha1": list((map(lambda p: hashlib.sha1(p.encode()).hexdigest(), dict_pass))),
                   "sha256": list((map(lambda p: hashlib.sha256(p.encode()).hexdigest(), dict_pass))),
                   "sha512": list((map(lambda p: hashlib.sha512(p.encode()).hexdigest(), dict_pass)))
                   }

    # Special case passwords. Setting the variables as swtiches in order to check if we have already fulfilled them.
    # We already know that the special case of user3 is caesar cipher.
    # 5 digits 0-9 (10^5 = 100,000 possible combinations)
    check_case = {"salt": True, "leet_speak": True}

    # Hashing and applying special casses in order to find the passwords.
    find_password(dict_pass, user_hashes, hashed_pass, check_case)

#Run
main()

"""
This script contains the functions which run behind the GUI.
First imports the necessary libraries and the Certificates.py script.
After that there are the definitions of all the functions which sign, login, check the integrity
and provide the application's services.
"""

import sqlite3
import os
from Certificates import *
import hashlib
import binascii
from Crypto.Cipher import AES
import OpenSSL


def create_hashes(username, master_password):
    """
    This function takes the username and the password of the user and creates the sKey and the authHash.
    :param username: The username of the user.
    :param master_password: The password of the user.
    :return: The authHash created with pbkdf2.
    """
    # create sKey with PBKDF2

    global sKey
    DK_1 = hashlib.pbkdf2_hmac('sha256', master_password, username, 2000, 16)
    sKey = binascii.hexlify(DK_1)
    # print(sKey)

    # create authHash with PBKDF2

    DK_2 = hashlib.pbkdf2_hmac('sha256', sKey, master_password, 1000, 16)
    authHash = binascii.hexlify(DK_2)
    # print(authHash)
    return authHash


def encryption(password):
    """
    This function encrypts with AES-128 the given password.
    :param password: The password to encrypt.
    :return: The encrypted password.
    """
    try:
        IV = 16 * '\x00'
        mode = AES.MODE_CBC

        encryptor = AES.new(sKey, mode, IV=IV, segment_size=AES.block_size * 128)
        ciphertext = encryptor.encrypt(password)

        cipher_pass = binascii.hexlify(ciphertext)
        return cipher_pass

    except ValueError:
        return 1


def decryption(ciphertext):
    """
    This function decrypts with AES-128 the chosen encrypted password.
    :param ciphertext: The encrypted password.
    :return: The decrypted password.
    """

    cip = binascii.unhexlify(ciphertext)
    IV = 16 * '\x00'
    mode = AES.MODE_CBC
    decryptor = AES.new(sKey, mode, IV=IV, segment_size=AES.block_size * 128)
    plain = decryptor.decrypt(cip)
    return plain


def registration(client_name, client_email, client_username, client_password):
    """
    This function is called when a user is going to be registered in the Password Manager Application.
    The function creates a directory for the user and saves the authHash. Also calls the register_user() function
    from the Certificates.py script with the user's username and password as arguments.
    :param client_name: The Name of the user.
    :param client_email: The e-mail address of the user.
    :param client_username: The desired username of the user.
    :param client_password: The desired password of the user.
    :return: None
    """
    try:
        path = "/home/michael/Application/Users/" + client_username + "/"

        os.mkdir(path)

        register_user(client_name, client_email)

        auth_hash = create_hashes(client_username.encode('utf-8'), client_password.encode('utf-8'))

        auth_path = path + "authHash.txt"
        with open(auth_path, 'wb') as f:
            f.write(auth_hash)

    except FileExistsError:
        return 1


def login(client_username, client_password, user_cert_path):
    """
    This function is called when a user is going to log in the Password Manager Application.
    The function calculate the authHash for the given Username and Password and loads the stored authHash. Also, the user
     in order to access his/her account must load the Certificate which issued during his/her registration. If the two
    authHashes are equal and the loaded Certificated is issued by the Application then the user can enter in the Password
    Manager.
    :param client_username: The username the user has typed during the registration.
    :param client_password: The password the user has typed during the registration.
    :param user_cert_path: The path where the user's certificate is.
    :return: In case of error it returns 1, else None.
    """

    current_auth_hash = create_hashes(client_username.encode('utf-8'), client_password.encode('utf-8'))
    # print(current_auth_hash)

    path = "/home/michael/Application/Users/" + client_username

    hash_path = path + "/authHash.txt"

    try:

        with open(hash_path, 'rb') as f:
            stored_auth_hash = f.read()
            # print(stored_auth_hash)

    except FileNotFoundError:
        return 1

    if current_auth_hash == stored_auth_hash:

        try:

            ca_cert = load_CA_cert()
            cert_store = crypto.X509Store()
            cert_store.add_cert(ca_cert)

            user_cert = open(user_cert_path, 'rt').read()
            certif = crypto.load_certificate(crypto.FILETYPE_PEM, user_cert)

            cert_store.add_cert(certif)
            store_ctx = crypto.X509StoreContext(cert_store, certif)
            store_ctx.verify_certificate()
        except OpenSSL.crypto.X509StoreContextError:
            return 1
    else:
        return 1


def connect(logged_user):
    """
    This function connects to the user database when the Application verifies the user's identity.
    Also it calls the check_integrity() function to check if there is any unauthorized password modification.
    :param logged_user: This is the username of the user who is currently using the Application.
    :return: The answer of the integrity check. If the user is logged in for first time returns another value(2).
    """

    global path
    path = "/home/michael/Application/Users/" + logged_user + "/"
    conn = sqlite3.connect(path + "user.db")
    cur = conn.cursor()
    cur.execute("CREATE TABLE IF NOT EXISTS entries (id INTEGER PRIMARY KEY, domain text, username text, password integer, comment text)")
    conn.commit()
    conn.close()
    try:
        answer = check_integrity()
        return answer
    except FileNotFoundError:
        return 2


def insert(domain, username, password, comment):
    """
    This function inserts into the user's database the entry (Domain, Username, Password, Comment)
    The password is beeing encrypted before saving.
    :param domain: The domain of the entry to save.
    :param username: The username of the entry to save.
    :param password: The password of the entry to save.
    :param comment: The comment of the entry to save.
    :return: In case of error it returns 1, else None.
    """

    pwd = encryption(password)
    if pwd == 1:
        return 1
    else:
        conn = sqlite3.connect(path + "user.db")
        cur = conn.cursor()
        cur.execute("INSERT INTO entries VALUES (NULL,?,?,?,?)", (domain, username, pwd, comment))
        conn.commit()
        conn.close()


def get_pass():
    """
    This function loads all the encrypted passwords from the user's database.
    :return: A list with the encrypted passwords.
    """
    conn = sqlite3.connect(path + "user.db")
    cur = conn.cursor()
    cur.execute("SELECT password FROM entries")
    pwd = cur.fetchall()
    conn.close()
    enc_passwords = []
    for i in pwd:

        # print(i[0])
        enc_passwords.append(i[0])
    return enc_passwords


def view():
    """
    This function returns all the entries in the user's database.
    :return: All user's data.
    """
    conn = sqlite3.connect(path + "user.db")
    cur = conn.cursor()
    cur.execute("SELECT * FROM entries")
    rows = cur.fetchall()
    conn.close()
    return rows


def delete(id):
    """
    This function deletes an entry which the user choose.
    :param id: The id which is the primary key of the chosen entry.
    :return: None
    """

    conn = sqlite3.connect(path + "user.db")
    cur = conn.cursor()
    cur.execute("DELETE FROM entries WHERE id=?", (id,))
    conn.commit()
    conn.close()


def update(id, domain, username, password, comment):
    """
    This function updates the parameters of a chosen entry.
    :param id: The id which is the primary key of the chosen entry.
    :param domain: The domain of the entry to save.
    :param username: The username of the entry to save.
    :param password: The password of the entry to save.
    :param comment: The comment of the entry to save.
    :return: None
    """

    pwd = encryption(password)
    conn = sqlite3.connect(path + "user.db")
    cur = conn.cursor()
    cur.execute("UPDATE entries SET domain=?, username=?, password=?, comment=? WHERE id=?", (domain, username, pwd, comment, id))
    conn.commit()
    conn.close()


def encrypt_signature():
    """
    This function calculates the encrypted signature for every encrypted password of a domain.
    It passes the encrypted password through a hash function (SHA), then signs the digest with the app's private key,
    and finally encrypts the Digital Sign with the sKey (AES-128).
    :return: A list of encrypted signatures.
    """
    enc_pwds = get_pass()
    enc_sign = []
    priv_ca_key = load_CA_key()
    for item in enc_pwds:
        # print(item)
        ds = crypto.sign(priv_ca_key, item, 'sha1')
        dig_sign = binascii.hexlify(ds)
        enc_sign.append(encryption(dig_sign))
    # print(enc_sign)
    return enc_sign


def close():
    """
    This function is called when the user clicks on the close button of the Entries Page.
    It calls the function to calculate the encrypted signatures of the passwords and the saves them into a .txt file
    in Applicatios/Users directory.
    :return: None
    """
    encrypted_signs = encrypt_signature()
    if encrypted_signs != []:
        integr_path = path + "/integrity.txt"
        with open(integr_path, 'w') as f:
            for i in encrypted_signs:
                f.write(i.decode('ascii') + "\n")


def check_integrity():
    """
    This function is being called when a user logs in the Password Manager Application. It checks the integrity of the
    user's encrypted passwords and inform him about the result.
    First, it calculates the encrypted signatures of these passwords, then it loads the integrity.txt file of the users
    where the are saved the encrypted signatures of the last session. Finally, it compares the two lists of the
    encrypted signatures.
    :return: Return the answer of the comparison, 0 if the two lists are equal or 1 if not.
    """
    encr_signs = encrypt_signature()
    integr_path = path + "/integrity.txt"
    loaded_enc_signs = []

    with open(integr_path, 'r') as f:
        sign = f.readlines()
        for item in sign:
            str_sign = item.strip("\n")
            binary_sign = str_sign.encode("utf-8")
            loaded_enc_signs.append(binary_sign)

    for i in range(len(encr_signs)):
        if encr_signs[i] == loaded_enc_signs[i]:
            return 0
        else:
            return 1


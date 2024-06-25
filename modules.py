from pymongo import MongoClient as Mc
import rsa
import hashlib
import base64
from datetime import datetime
from bson.objectid import ObjectId

# establishing a connection to the mongodb database
client = Mc("localhost", 27017)
db = client.PasswordVault
psw_col = db.password
users = db.user

# get the public and private keys for the data encryption and decryption
with open("public.pem", "rb") as f:
    public_key = rsa.PublicKey.load_pkcs1(f.read())

with open("private.pem", "rb") as f:
    private_key = rsa.PrivateKey.load_pkcs1(f.read())

hash_alg = hashlib.sha256()


class Vault:
    def __init__(self, user, site, password):
        self.user = user
        self.site = site
        self.password = password

    @staticmethod
    def add_user(username, email, password, confirm_password):
        if password != confirm_password:
            print("Passwords do not match!")
        else:
            user_hash = hashing_func(username.upper())
            email_hash = hashing_func(email.lower())
            psw_hash = hashing_func(password)

            users.insert_one({
                "username": user_hash,
                "email": email_hash,
                "password": psw_hash,
                "created_at": datetime.now()
            })
            print("User creation successful!")

    @staticmethod
    def delete_user(username, site):
        # delete user
        pass

    @staticmethod
    def add_password(user, user_id, site, password):
        user_encrypt = rsa.encrypt(user.encode(), public_key)
        user_64 = base64.b64encode(user_encrypt).decode("utf-8")
        hash_alg.update(user.upper().encode())
        user_hash = hash_alg.hexdigest()

        psw_encrypt = rsa.encrypt(password.encode(), public_key)
        psw_64 = base64.b64encode(psw_encrypt).decode('utf-8')

        psw_col.insert_one({
            "user_id": ObjectId(user_id),
            "user": user_64,
            "usr": user_hash,
            "site": site.upper(),
            'password': psw_64,
            "create_at": datetime.now()
        })
        print(f"[Created!]: user: {user}, site: {site}, password: {password} has been added to the database")

    @staticmethod
    def get_password(user, site):
        hash_alg.update(user.encode())
        user_hash = hash_alg.hexdigest()

        for usr in psw_col.find({"usr": user_hash, "site": site.upper()}):
            psw_64 = usr['password']
            psw_decode = base64.b64decode(psw_64)
            psw = rsa.decrypt(psw_decode, private_key)
            psw = psw.decode()
            print(f"[Collecting Password...]: The password is: {psw}")

    @staticmethod
    def update_password(user, site, new_password):
        # update password
        hash_alg.update(user.upper().encode())
        user_hash = hash_alg.hexdigest()

        psw_encrypt = rsa.encrypt(new_password.encode(), public_key)
        psw_64 = base64.b64encode(psw_encrypt).decode("utf-8")

        psw_col.update_one({"usr": user_hash, "site": site.upper()}, {"$set": {"password": psw_64}})
        print("[Password Update Successful!]")

    @staticmethod
    def delete_password(user, site):
        user_hash = hashing_func(user.upper())

        deleted = psw_col.delete_one({"usr": user_hash, "site": site.upper()})
        print(deleted)
        print(user_hash)
        print(["DELETE SUCCESSFUL!"])


def hashing_func(text):
    hashing_alg = hashlib.sha256()
    # text = text.encode()
    hashing_alg.update(text.encode())
    return hashing_alg.hexdigest()


def login_user(username):
    usr_hash = hashing_func(username.upper())
    # psw_hash = hashing_func(password)

    user_exists = users.find_one({"username": usr_hash})
    if not user_exists:
        print(f"User: '{username}' is not recognised!")
    else:
        psw = user_exists.get("password")
        count = 0
        while True:
            if count == 3:
                print("Failed more than 3 times!")
                break

            password = input("Enter Password: ")
            psw_hash = hashing_func(password)

            if psw_hash == psw:
                print(f"Login Successful!")
                print(f"Welcome '{username}'")
                user_id = user_exists.get("_id")
                return user_id
                # break
            else:
                print("Wrong Password!, Try again")
                count += 1
                print(f'[Number of Tries Left]: {3-count}')


def psw_vault(user_id):
    print("[Vault is now running...]", f"Time: {datetime.now()}")
    a = 'Press "A" to add new password'
    g = 'Press "G" to get password'
    u = 'Press "U" to update user'
    d = 'Press "D" to delete user'
    q = "Press 'Q' to quite!"

    method = input(f'{a} \n{g} \n{u} \n{d} \n{q} \n: ')

    if method.upper() == 'A':
        print("[Add Password!]")
        user = input("Enter Username or Email: ")
        site = input("Enter the site: ")
        psw = input("Enter the password: ")
        Vault.add_password(user=user, user_id=user_id, site=site, password=psw)

    elif method.upper() == 'G':
        print("Get Password!")
        user = input("Enter username: ")
        site = input("Enter site: ")
        Vault.get_password(user=user, site=site)

    elif method.upper() == 'U':
        print("Update User")
        user = input("Enter username: ")
        site = input("Enter site: ")
        psw = input("Enter new Password: ")
        Vault.update_password(user=user, site=site, new_password=psw)

    elif method.upper() == 'D':
        print(["Delete User "])
        user = input("Enter Username or Email: ")
        site = input("Enter site: ")

        Vault.delete_password(user=user, site=site)
    elif method.upper() == "Q":
        print("Quite!!")
        logged_in = False
        return logged_in
    else:
        print(f"Failed to understand Input: {method}")
        logged_in = False
        return logged_in

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
        user_hash = hashing_func(user.upper())

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
        user_hash = hashing_func(user.upper())
        print("1 check")

        for usr in psw_col.find({"usr": user_hash, "site": site.upper()}):
            print("2 Check")
            psw_64 = usr['password']
            psw_decode = base64.b64decode(psw_64)
            psw = rsa.decrypt(psw_decode, private_key)
            psw = psw.decode()
            return f"The password is: '{psw}' "

    @staticmethod
    def update_password(user, site, new_password):
        # update password
        user_hash = hashing_func(user)

        psw_encrypt = rsa.encrypt(new_password.encode(), public_key)
        psw_64 = base64.b64encode(psw_encrypt).decode("utf-8")

        psw_col.update_one({"usr": user_hash, "site": site.upper()}, {"$set": {"password": psw_64}})
        print("[Password Update Successful!]")

    @staticmethod
    def delete_password(user, site):
        user_hash = hashing_func(user.upper())

        deleted = psw_col.delete_one({"usr": user_hash})
        print(deleted)
        print(user_hash)
        print(["DELETE SUCCESSFUL!"])


def hashing_func(text):
    hashing_alg = hashlib.sha256()
    hashing_alg.update(text.encode())
    return hashing_alg.hexdigest()


def login_user(username, password, text_field, psw_input, user_input):
    usr_hash = hashing_func(username.upper())
    psw_hash = hashing_func(password)

    user_exists = users.find_one({"username": usr_hash})
    if not user_exists:
        text_field.insert("end", f"User: '{username}' is not recognised! \n")
        user_input.delete(0, "end")
        return None
    else:
        psw = user_exists.get("password")
        if psw_hash == psw:
            text_field.insert("end", "Login Successful! \n")
            return user_exists.get("_id")
        else:
            text_field.insert("end", "Login Failed! \n")
            psw_input.delete(0, "end")
            return None

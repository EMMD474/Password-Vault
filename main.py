from modules import Vault, login_user, psw_vault

print("[PASSWORD VAULT IS STARTING...]")
print("Sign In!")
print("Type 'c' to create new user")
username = input("Enter Username: ")

if username.upper() == "C":
    print("Create New User!")
    username = input("Enter username: ")
    email = input("Enter Email Address: ")
    password = input("Enter Password: ")
    confirm_password = input("Confirm Password: ")

    Vault.add_user(username=username, email=email, password=password, confirm_password=confirm_password)
else:
    user_id = login_user(username=username)
    if user_id:
        while True:
            logged_in = psw_vault(user_id=user_id)
            if not logged_in:
                print("[SERVER]: User has logged out!")
                break

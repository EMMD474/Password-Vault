import customtkinter as c

from modules import Vault, login_user

c.set_appearance_mode("system")
c.set_default_color_theme("blue")

max_attempts = 3
login_attempts = 0
_id = ""
inbox = None


def login():
    global login_attempts
    global _id

    usr: str = user_input.get()
    psw: str = password_input.get()

    user_id = login_user(usr, psw, login_text_box, password_input, user_input)
    if user_id:
        home_screen(usr)
        _id = user_id
    else:
        login_attempts += 1
        if login_attempts >= max_attempts:
            login_text_box.insert("end", "Failed more than 3 times!")
            login_btn.configure(state="disabled")
        else:
            login_text_box.insert("end", f"Attempt {login_attempts} of {max_attempts} \n")


def login_screen():
    heading = c.CTkLabel(frame, text="PV", text_color="teal", font=('sans-serif', 16))
    heading.pack(pady=10, padx=10)
    title_label = c.CTkLabel(frame, text="Login", text_color=("#000", "#fff"), font=("sans-serif", 12))
    title_label.pack(pady=5, padx=10)
    global user_input
    user_input = c.CTkEntry(master=frame, height=30, width=200, placeholder_text="Enter username or email",
                            border_color="teal")
    user_input.pack(pady=5, padx=5)
    global password_input
    password_input = c.CTkEntry(master=frame, height=30, width=200, placeholder_text="Enter Password",
                                border_color="teal",
                                show="*")
    password_input.pack(pady=10, padx=5)
    global login_btn
    login_btn = c.CTkButton(master=frame, height=25, width=100, corner_radius=5, text="Login", fg_color="#057b7b",
                            hover_color="#026161", command=login)
    login_btn.pack(pady=10, padx=5)
    global login_text_box
    login_text_box = c.CTkTextbox(frame, width=300)
    login_text_box.pack(pady=10, padx=10, fill="both", expand=True)


def home_screen(username):
    for widget in frame.winfo_children():
        widget.destroy()

    print(_id)

    welcome = c.CTkLabel(frame, text=f"Welcome {username}", text_color=("#000", "#fff"), font=("sans-serif", 12))
    welcome.pack(pady=5, padx=10)

    method_list = ["Get Password", "Add Password", "Update Password", "Delete Password"]
    global method_menu
    method_menu = c.CTkOptionMenu(frame, values=method_list, fg_color="#027171", button_color="#029898",
                                  button_hover_color="#025151", command=lambda method: fields(method_menu.get()))
    method_menu.pack(pady=10, padx=10)
    method_menu.set("Get Password")

    fields("Get Password")


def fields(method):
    global inbox
    for widget in frame.winfo_children():
        if isinstance(widget, c.CTkFrame):
            widget.destroy()
        if inbox is not None:
            inbox.destroy()

    inputs_frame = c.CTkFrame(frame)
    inputs_frame.pack(pady=10, padx=10, fill="both", expand=True)

    global user
    user = c.CTkEntry(inputs_frame, height=30, width=200, placeholder_text="Enter user or email", border_color="teal")
    user.pack(pady=10, padx=10)
    global site
    site = c.CTkEntry(inputs_frame, height=30, width=200, placeholder_text="Enter site", border_color="teal")
    site.pack(pady=5, padx=10)

    global psw_input
    if method == "Add Password":
        psw_input = c.CTkEntry(inputs_frame, height=30, width=200, placeholder_text="Enter Password",
                               border_color="teal")
        psw_input.pack(pady=5, padx=10)
        global new_password
    if method == "Update Password":
        new_password = c.CTkEntry(inputs_frame, height=30, width=200, placeholder_text="New Password",
                                  border_color="teal")
        new_password.pack(pady=5, padx=10)
    add_btn = c.CTkButton(inputs_frame, text=method, fg_color="teal", hover_color="#025151",
                          command=lambda: operate(method))
    add_btn.pack(pady=5, padx=10)

    inbox = c.CTkTextbox(frame, width=200)
    inbox.pack(pady=2, padx=5, fill="both", expand=True)
    global text_box
    text_box = inbox


def operate(method):
    get_user: str = user.get()
    get_site: str = site.get()
    get_password = 'none'
    new_psw = "None"

    if method == "Add Password":
        get_password: str = psw_input.get()
    elif method == "Update Password":
        new_psw: str = new_password.get()

    if get_user == "":
        text_box.insert("end", "Username cannot be blank! \n")
    if get_site == "":
        text_box.insert("end", "Site cannot be blank! \n")
    else:
        if method == "Add Password":
            Vault.add_password(get_user, _id, get_site, get_password)
            text_box.insert("end", "Password Added!")
            user.delete(0, "end")
            site.delete(0, "end")
            psw_input.delete(0, "end")
        elif method == "Get Password":
            psw_result = Vault.get_password(get_user, get_site)
            if psw_result:
                text_box.insert("end", psw_result)
            else:
                text_box.insert("end", "No Password found!")
            user.delete(0, "end")
            site.delete(0, "end")
        elif method == "Update Password":
            Vault.update_password(get_user, get_site, new_password=new_psw)
            text_box.insert("end", "Password has been Updated!!")
            user.delete(0, "end")
            site.delete(0, "end")
        elif method == "Delete Password":
            Vault.delete_password(get_user, get_site)
            text_box.insert("end", "Password Deleted")
            user.delete(0, "end")
            site.delete(0, "end")
        else:
            print("Input not recognized")


root = c.CTk()
root.geometry("360x350")
frame = c.CTkFrame(root)
frame.pack(pady=20, padx=20, fill="both", expand=True)

login_screen()
root.mainloop()

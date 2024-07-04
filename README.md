## Password Vault Application

### Description
A secure password vault application built using Python, CustomTkinter for the GUI, and MongoDB for the database. This application allows users to securely manage their passwords, including adding, retrieving, updating, and deleting passwords.

### Features
- **Secure Login System**: User authentication with hashing and encryption.
- **Password Encryption**: Uses RSA encryption to securely store passwords.
- **Password Management**: Add, retrieve, update, and delete passwords.
- **User-friendly Interface**: Built with CustomTkinter for an intuitive GUI.

### Installation

#### Prerequisites
- Python 3.10+
- MongoDB
- Required Python packages (listed in `requirements.txt`)

#### Steps
1. **Clone the repository**:
   ```bash
   git clone https://github.com/EMMD474/Password-Vault.git
   cd password-vault
   ```
2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
3. **Setup MongoDB**:
   - Ensure MongoDB is running on `localhost:27017`.
   - Configure the database and collections if necessary.

4. **Generate RSA keys**:
   - Generate RSA keys and save them as `public.pem` and `private.pem` in the project directory.

5. **Run the application**:
   ```bash
   python main.py
   ```

### Usage
1. **Login Screen**: Enter your username and password to log in.
2. **Home Screen**: Welcome message and options for managing passwords.
3. **Password Management**: Choose an action (Get, Add, Update, Delete) and follow the prompts to manage your passwords.

### Code Overview

#### `main.py`
- Handles the GUI and user interactions.
- Implements the login screen and home screen functionalities.

#### `modules.py`
- Contains the `Vault` class for password management.
- Handles user authentication, password encryption, and database interactions.

### Security
- **Encryption**: RSA encryption for storing passwords.
- **Hashing**: SHA-256 hashing for user credentials.

### Contributions
Feel free to fork the repository, make improvements, and submit pull requests. All contributions are welcome!

### Contact
For any questions or feedback, please contact [EMMANUEL BANDA] at [emmdb474@gmail.com].


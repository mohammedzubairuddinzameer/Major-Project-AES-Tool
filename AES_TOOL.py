import streamlit as st
import sqlite3
import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ----------------- DATABASE SETUP -----------------
conn = sqlite3.connect("users.db", check_same_thread=False)
c = conn.cursor()

c.execute("""CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT
)""")

c.execute("""CREATE TABLE IF NOT EXISTS history (
    username TEXT,
    action TEXT,
    filename TEXT
)""")

conn.commit()

# ----------------- HELPER FUNCTIONS -----------------
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def add_user(username, password):
    c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
    conn.commit()

def authenticate(username, password):
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hash_password(password)))
    return c.fetchone()

def save_history(username, action, filename):
    c.execute("INSERT INTO history (username, action, filename) VALUES (?, ?, ?)", (username, action, filename))
    conn.commit()

def get_history(username):
    c.execute("SELECT action, filename FROM history WHERE username=?", (username,))
    return c.fetchall()

# ----------------- AES-256 FUNCTIONS -----------------
def encrypt_file(file_bytes, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(file_bytes) + encryptor.finalize()
    return iv + encrypted_data

def decrypt_file(file_bytes, key):
    iv = file_bytes[:16]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(file_bytes[16:]) + decryptor.finalize()
    return decrypted_data

# ----------------- STREAMLIT APP -----------------
st.title("🔐 Advanced Encryption Tool (AES-256)")

# Session state for login
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""

menu = ["Login", "Sign Up"]
choice = st.sidebar.selectbox("Menu", menu)

# ----------------- SIGN UP -----------------
if choice == "Sign Up":
    st.subheader("📝 Create New Account")
    new_user = st.text_input("Username")
    new_pass = st.text_input("Password", type="password")
    if st.button("Sign Up"):
        c.execute("SELECT * FROM users WHERE username=?", (new_user,))
        if c.fetchone():
            st.error("❌ Username already exists!")
        elif new_user == "" or new_pass == "":
            st.error("⚠️ Please enter both username and password.")
        else:
            add_user(new_user, new_pass)
            st.success("✅ Account created successfully! Please login.")

# ----------------- LOGIN -----------------
elif choice == "Login":
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        result = authenticate(username, password)
        if result:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.success(f"✅ Logged in as {username}")
        else:
            st.error("❌ Invalid Username or Password")

# ----------------- MAIN APP AFTER LOGIN -----------------
if st.session_state.logged_in:
    st.sidebar.success(f"Welcome, {st.session_state.username} 👋")

    mode = st.sidebar.radio("Choose Mode", ["Encrypt", "Decrypt", "History", "Logout"])
    password = st.sidebar.text_input("Enter Secret Key (32 chars)", type="password")

    if mode in ["Encrypt", "Decrypt"]:
        uploaded_file = st.file_uploader("Upload File", type=None)

        if uploaded_file and password:
            if len(password) != 32:
                st.error("❌ Key must be exactly 32 characters for AES-256!")
            else:
                key = password.encode("utf-8")
                file_bytes = uploaded_file.read()

                if mode == "Encrypt":
                    encrypted_data = encrypt_file(file_bytes, key)
                    st.success("✅ File encrypted successfully!")
                    save_history(st.session_state.username, "Encrypted", uploaded_file.name)
                    st.download_button("⬇️ Download Encrypted File",
                                       encrypted_data,
                                       file_name=f"{uploaded_file.name}.enc",
                                       mime="application/octet-stream")

                elif mode == "Decrypt":
                    try:
                        decrypted_data = decrypt_file(file_bytes, key)
                        st.success("✅ File decrypted successfully!")
                        save_history(st.session_state.username, "Decrypted", uploaded_file.name)
                        st.download_button("⬇️ Download Decrypted File",
                                           decrypted_data,
                                           file_name=f"decrypted_{uploaded_file.name.replace('.enc','')}",
                                           mime="application/octet-stream")
                    except Exception as e:
                        st.error("❌ Decryption failed! Check your key or file.")

    elif mode == "History":
        st.subheader("📜 Your Encryption/Decryption History")
        history = get_history(st.session_state.username)
        if history:
            for action, filename in history:
                st.write(f"➡️ {action} : {filename}")
        else:
            st.info("No history found.")

    elif mode == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.success("✅ Logged out successfully.")

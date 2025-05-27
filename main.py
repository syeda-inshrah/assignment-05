import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Key Generation + Cipher (Stable) ---
if 'KEY' not in st.session_state:
    st.session_state.KEY = Fernet.generate_key()

cipher = Fernet(st.session_state.KEY)

# --- Session State Initialization ---
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}  # stores encrypted text with the hashed passkey
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

# --- Helper Functions ---
def hash_passkey(passkey):
    """ Hashes the passkey using SHA-256 """
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text):
    """ Encrypts the provided text using Fernet encryption """
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    """ Decrypts the provided encrypted text using Fernet decryption """
    return cipher.decrypt(encrypted_text.encode()).decode()

# --- Streamlit UI Setup ---
st.set_page_config(page_title="Secure Data App", layout="centered")
st.title("🔐 Secure Data Encryption System")

# --- Login Page ---
if st.session_state.failed_attempts >= 3:
    st.subheader("🔑 Reauthorize to Continue")
    admin_pass = st.text_input("Enter Admin Password", type="password")
    if st.button("Login as Admin"):
        if admin_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized! You may try again.")
            st.experimental_rerun()
        else:
            st.error("❌ Incorrect admin password.")
else:
    tab1, tab2 = st.tabs(["🔒 Store Data", "🔓 Retrieve Data"])

    # --- Store Data Tab ---
    with tab1:
        st.subheader("📥 Store Your Secret Data")
        col1, col2 = st.columns(2)
        with col1:
            user_data = st.text_area("Enter the data you want to encrypt")
        with col2:
            store_passkey = st.text_input("Create a passkey", type="password")

        if st.button("Encrypt & Save"):
            if user_data and store_passkey:
                # Encrypt data and hash the passkey
                encrypted_data = encrypt_data(user_data)
                hashed_passkey = hash_passkey(store_passkey)

                # Store the encrypted data with its hashed passkey
                st.session_state.stored_data[encrypted_data] = hashed_passkey

                st.success("✅ Data saved securely!")
                with st.expander("🔐 Your Encrypted Data"):
                    st.code(encrypted_data, language="text")
            else:
                st.warning("⚠️ Please enter both data and passkey.")

    # --- Retrieve Data Tab ---
    with tab2:
        st.subheader("🔍 Retrieve Encrypted Data")
        col1, col2 = st.columns(2)
        with col1:
            encrypted_text = st.text_area("Paste encrypted text here")
        with col2:
            retrieve_passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt Data"):
            if encrypted_text and retrieve_passkey:
                # Hash the entered passkey
                hashed_input = hash_passkey(retrieve_passkey)

                # Retrieve stored data and compare hashes
                stored_hash = st.session_state.stored_data.get(encrypted_text)

                if stored_hash == hashed_input:
                    decrypted_data = decrypt_data(encrypted_text)
                    st.success("✅ Decrypted Successfully!")
                    st.code(decrypted_data, language="text")
                    st.session_state.failed_attempts = 0  # Reset failed attempts on success
                else:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = 3 - st.session_state.failed_attempts
                    if remaining_attempts > 0:
                        st.error(f"❌ Wrong passkey! Attempts left: {remaining_attempts}")
                    else:
                        st.error("❌ Too many failed attempts! Please reauthorize.")
            else:
                st.warning("⚠️ Please enter both fields.")

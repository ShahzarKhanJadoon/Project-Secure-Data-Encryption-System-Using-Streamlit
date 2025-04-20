# SecureVault - Advanced Data Protection System

# Core Dependencies
import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac

# Application Configuration
st.set_page_config(
    page_title="SecureVault",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="expanded"
)

# Security Configuration
VAULT_FILE = "user_vault.json"
SECURITY_SALT = b"ultra_secure_salt_value"
MAX_LOGIN_ATTEMPTS = 3
LOCKOUT_PERIOD = 60  # seconds

# Session Management
if "current_user" not in st.session_state:
    st.session_state.current_user = None

if "login_attempts" not in st.session_state:
    st.session_state.login_attempts = 0

if "lockout_end" not in st.session_state:
    st.session_state.lockout_end = 0

# Core Functions
def load_vault():
    if os.path.exists(VAULT_FILE):
        with open(VAULT_FILE, "r") as vault:
            return json.load(vault)
    return {}

def save_vault(vault_data):
    with open(VAULT_FILE, "w") as vault:
        json.dump(vault_data, vault)

def create_security_key(secret):
    key = pbkdf2_hmac('sha256', secret.encode(), SECURITY_SALT, 100000)
    return urlsafe_b64encode(key)

def secure_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SECURITY_SALT, 100000).hex()

def protect_data(data, secret):
    try:
        key = create_security_key(secret)
        cipher = Fernet(key)
        return cipher.encrypt(data.encode()).decode()
    except Exception as e:
        st.error(f"Protection failed: {str(e)}")
        return None

def reveal_data(protected_data, secret):
    try:
        key = create_security_key(secret)
        cipher = Fernet(key)
        return cipher.decrypt(protected_data.encode()).decode()
    except Exception as e:
        st.error(f"Revelation failed: {str(e)}")
        return None

# Load User Vault
user_vault = load_vault()

# Main Interface
st.title("🔒 SecureVault")
st.markdown("---")

# Navigation
nav_options = ["🏠 Home", "🔐 Login", "📝 Register", "💾 Store Secret", "🔓 Retrieve Secret"]
selected_page = st.sidebar.radio("Navigation", nav_options)

if selected_page == "🏠 Home":
    st.header("Welcome to SecureVault")
    st.markdown("""
    ### Your Personal Data Protection System
    
    SecureVault provides:
    - 🔒 Military-grade encryption
    - 👤 User authentication
    - 💾 Secure data storage
    - 🔓 Safe data retrieval
    
    Get started by registering or logging in!
    """)

elif selected_page == "📝 Register":
    st.header("Create Your Vault")
    new_username = st.text_input("Choose Your Username")
    new_password = st.text_input("Set Your Password", type="password")
    
    if st.button("Create Vault"):
        if new_username and new_password:
            if new_username in user_vault:
                st.warning("This username is already taken")
            else:
                user_vault[new_username] = {
                    "password": secure_password(new_password),
                    "secrets": []
                }
                save_vault(user_vault)
                st.success("Vault created successfully! You can now login.")
        else:
            st.error("Please provide both username and password")

elif selected_page == "🔐 Login":
    st.header("Access Your Vault")
    if time.time() < st.session_state.lockout_end:
        remaining_time = int(st.session_state.lockout_end - time.time())
        st.error(f"⚠️ Too many failed attempts. Please wait {remaining_time} seconds.")
        st.stop()
    
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Unlock Vault"):
        if username in user_vault and user_vault[username]["password"] == secure_password(password):
            st.session_state.current_user = username
            st.session_state.login_attempts = 0
            st.success(f"Welcome back, {username}! Your vault is unlocked.")
        else:
            st.session_state.login_attempts += 1
            attempts_left = MAX_LOGIN_ATTEMPTS - st.session_state.login_attempts
            st.error(f"❌ Invalid credentials. {attempts_left} attempts remaining.")

            if st.session_state.login_attempts >= MAX_LOGIN_ATTEMPTS:
                st.session_state.lockout_end = time.time() + LOCKOUT_PERIOD
                st.error(f"⚠️ Account locked. Try again in {LOCKOUT_PERIOD} seconds.")
                st.stop()

elif selected_page == "💾 Store Secret":
    if not st.session_state.current_user:
        st.warning("🔒 Please login to access your vault")
    else:
        st.header("Store Your Secret")
        secret_data = st.text_area("Enter your secret message")
        protection_key = st.text_input("Enter your protection key", type="password")

        if st.button("Protect Data"):
            if secret_data and protection_key:
                protected = protect_data(secret_data, protection_key)
                if protected:
                    user_vault[st.session_state.current_user]["secrets"].append(protected)
                    save_vault(user_vault)
                    st.success("✅ Your secret is now protected!")
                    st.code(protected, language="text")
            else:
                st.error("Please provide both secret message and protection key")

elif selected_page == "🔓 Retrieve Secret":
    if not st.session_state.current_user:
        st.warning("🔒 Please login to access your vault")
    else:
        st.header("Retrieve Your Secret")
        user_secrets = user_vault.get(st.session_state.current_user, {}).get("secrets", [])

        if not user_secrets:
            st.info("📭 Your vault is empty")
        else:
            st.write("🔐 Protected Secrets:")
            for i, secret in enumerate(user_secrets):
                st.code(secret, language="text")
            
            protected_input = st.text_area("Enter the protected secret")
            protection_key = st.text_input("Enter your protection key", type="password")

            if st.button("Reveal Secret"):
                if protected_input and protection_key:
                    revealed = reveal_data(protected_input, protection_key)
                    if revealed:
                        st.success("✅ Secret revealed successfully!")
                        st.text_area("Your Secret", revealed, height=200)
                    else:
                        st.error("❌ Failed to reveal secret. Check your protection key.")
                else:
                    st.error("Please provide both protected secret and protection key")

              

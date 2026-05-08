from crypto import hash_password
import secrets
import db 
import sqlite3
import uuid 
from datetime import datetime
import secrets

#ESTABLISHING CONNECTION WITH THE DATABASE --------------------------------------

connection = db.get_connection()
#register-------------------------------------------------------------------------------

def register(username: str, password: str) -> tuple[bool, str]:
    """
    register nouvel user .
    retourne tuple si vrai + msg explicatif. 
    """
    username=username.strip().lower()
    if not username :
        return False, "Le nom d'utilisateur ne peut pas être vide."
    if not password.strip():
        return False, "Le mot de passe ne peut pas être vide."
    if len(username) < 3:
        return False, "Le nom d'utilisateur doit contenir au moins 3 caractères."
    
    #verification de la solidite du mot de passe -------------------------------
    if len(password) < 6:
        return False, "Le mot de passe doit contenir au moins 6 caractères."
    if not any(c.isupper() for c in password):
        return False ,"Le mot de passe doit contenir une majuscule"
    if not any(c.islower() for c in password):
        return False , "Le mot de passe doit contenir une minuscule"
    if not any(c.isdigit() for c in password):
        return False, "Le mot de passe doit contenir un chiffre"
    special_chars = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"

    if not any(c in special_chars for c in password):
        return False, "Le mot de passe doit contenir un caractère spécial" 
    
    confirm_password = input("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match")
        return False ,"passwords do not match "
    #----------------------------------------------------------------
    
    #verification de l'existence de l'utilisateur dans la base de données

    if db.user_exists(username):
        print("Username already exists")
        return   False ," utilisateur existant "
    
    #-------------------------------------------------------------------

    #generating user_id------------------------------------------
    user_id = str(uuid.uuid4())
    #------------------------------------------------------------
    
    #hashing password

    salt = secrets.token_hex(16)
    password_hash = hash_password(password, salt)
    #------------------------------------------------------------
    
    db.create_user(
        user_id=user_id,
        username=username,
        password_hash=password_hash,
        salt=salt
    )
    
    db.get_connection().close()


    return True, f"Compte '{username}' créé avec succès."



#authentication function --------------------------------------------------------------

def authenticate(username: str, password: str) -> tuple[bool, str] :
    """
    Authentifie un utilisateur.
    Retourne (True, message) ou (False, message d'erreur).
    """
    try:
        username=username.strip().lower()
        if not username :
            return False, "Le nom d'utilisateur ne peut pas être vide."
        if not password.strip():
            return False, "Le mot de passe ne peut pas être vide." 

        user = db.get_user_by_username(username)
        if user is None:
            return False, "Nom d'utilisateur ou mot de passe incorrect."

        stored_hash = user["password_hash"]
        salt = user["salt"]

        if hash_password(password, salt)  == stored_hash :
            print("Authentication successful")
            print(f"Welcome, {user['username']}!")
            return True, {
            "user_id": user["user_id"],
            "username": user["username"],
            "role": user["role"]
            } 
        else:
            return False, "Nom d'utilisateur ou mot de passe incorrect."
    except Exception as e:

        return False, f"Erreur d'authentification : {e}"
from matplotlib.path import Path

import core.objects as objects
from core.crypto import hash_password
import secrets
import core.db as db 
import sqlite3
import uuid 
from datetime import datetime, timedelta
import secrets
STORAGE_ROOT = Path(__file__).parent.parent / "storage" / "users"
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
    password_hash = hash_password(password, salt)[0]
    #------------------------------------------------------------
    
    db.create_user(
        user_id=user_id,
        username=username,
        password_hash=password_hash,
        salt=salt
    )
    
    user_dir = STORAGE_ROOT / user_id
    user_dir.mkdir(parents=True, exist_ok=True )

    db.get_connection().close()


    return True, f"Compte '{username}' créé avec succès."



#authentication function --------------------------------------------------------------

def authenticate(username: str, password: str) -> tuple[bool, objects.User | str]: 
    """
    Authentifie un utilisateur.
    Retourne (True, user) ou (False, message d'erreur).
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

        if hash_password(password, salt)[0] == stored_hash:
            print("Authentication successful")
            print(f"Welcome, {user['username']}!")
            #create current user object
            current_user = objects.User(
                user_id=user["user_id"],
                username=user["username"],
                password_hash=user["password_hash"],
                salt=user["salt"],
                role=user["role"]
            )
            #return the user object for further use (e.g., session creation)
            return True, current_user
        else:
            return False, "Nom d'utilisateur ou mot de passe incorrect."
    except Exception as e:

        return False, f"Erreur d'authentification : {e}"
    
def create_session(user_id: str) -> objects.Session :
    """Crée une session pour un utilisateur donné et retourne l'objet session."""
    token = secrets.token_hex(32)
    created_at = datetime.now()
    try:
        with db.get_connection() as conn:
            conn.execute(
                "INSERT INTO Sessions (session_id, user_id , created_at , expires_at) VALUES (?, ?, ?, ?)",
                (token, user_id, datetime.now() , created_at + timedelta(minutes=10))
            )
    except sqlite3.Error as e :
        print(f"Erreur lors de la création de session : {e}")
        return False
    current_Session = objects.Session(session_id=token, user_id=user_id, created_at=created_at, expires_at=created_at + timedelta(minutes=10))
    return current_Session 

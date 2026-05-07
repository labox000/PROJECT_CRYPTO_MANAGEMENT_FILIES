from crypt import hash_password
from users import User, add_user, get_user, user_exists
import sqlite3
import uuid 
from datetime import datetime

#ESTABLISHING CONNECTION WITH THE DATABASE --------------------------------------

connection = sqlite3.connect("User_Management.db")
cursor = connection.cursor()

#--------------------------------------------------------------------------------

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

    cursor.execute(""" SELECT 1 FROM Users WHERE username = ? """, (username,))
    if cursor.fetchone():
        print("Username already exists")
        return   False ," utilisateur existant "
    
    #-------------------------------------------------------------------

    #generating user_id------------------------------------------
    user_id = str(uuid.uuid4())
    #------------------------------------------------------------
    
    #hashing password
    password_hash, salt = hash_password(password)
    #------------------------------------------------------------
    
    creation_date = datetime.now()
    
    #Adding to database
    try:

        
        cursor.execute("""
            INSERT INTO Users
            (user_id, username, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            user_id,
            username,
            password_hash,
            "user",
            creation_date
        ))

        connection.commit()

        print("User registered successfully")

    except sqlite3.IntegrityError:

        return False , "User already existant"

    except sqlite3.Error as e:

        return False , f"Database error: {e}"
    
    connection.close()


    return True, f"Compte '{username}' créé avec succès."
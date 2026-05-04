import json
import os
 
USERS_FILE = os.path.join("data", "users.json")
class User:
 
    def __init__(self, username: str, password_hash: str, salt: str):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
 
    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "salt": self.salt,
        }
 
    #methode stat
    def from_dict(data: dict) -> "User":
        return User(
            username=data["username"],
            password_hash=data["password_hash"],
            salt=data["salt"],
        )
 
    def __repr__(self):
        return f"User(username={self.username!r})" #affichage user
    
def _load_users() -> dict:
    """Charge le fichier users.json et retourne un dict {username: User}."""
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return {username: User.from_dict(data) for username, data in raw.items()}
 
 
def _save_users(users: dict) -> None:
    """Sauvegarde le dict {username: User} dans users.json."""
    os.makedirs("data", exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(
            {username: user.to_dict() for username, user in users.items()},
            f,
            indent=2,
            ensure_ascii=False,
        )
 
 
def get_user(username: str):
    """Retourne un objet User ou None si introuvable."""
    users = _load_users()
    return users.get(username)
 
 
def add_user(user: User) -> bool:
    """
    Ajoute un nouvel utilisateur.
    Retourne False si le nom d'utilisateur existe déjà.
    """
    users = _load_users()
    if user.username in users:
        return False
    users[user.username] = user
    _save_users(users)
    return True
 
 
def user_exists(username: str) -> bool:
    """Vérifie si un utilisateur existe."""
    return _load_users().get(username) is not None
def register(username: str, password: str) -> tuple[bool, str]:
    """
    register nouvel user .
    retourne tuple si vrai + msg explicatif.
    """
    if not username.strip():
        return False, "Le nom d'utilisateur ne peut pas être vide."
    if len(password) < 6:
        return False, "Le mot de passe doit contenir au moins 6 caractères."
    if user_exists(username):
        return False, f"L'utilisateur '{username}' existe déjà."
 
    password_hash, salt = hash_password(password)
    user = User(username=username, password_hash=password_hash, salt=salt)
    add_user(user)
    return True, f"Compte '{username}' créé avec succès."
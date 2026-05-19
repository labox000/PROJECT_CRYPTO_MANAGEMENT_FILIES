"""
authentification.py — Inscription, connexion, sessions, modification de compte.
 
Fonctions publiques :
    register(username, password, confirm_password)              → (bool, str)
    login(username, password)                                   → (bool, User | str)
    logout(session_id, user_id)                                 → None
    create_user_session(user_id)                                → Session
    change_username(user_id, new_username, current_password)    → (bool, str)
    change_password(user_id, old_password, new_password, confirm) → (bool, str)
    admin_delete_user(admin_user, target_user_id)               → (bool, str)
    admin_reset_password(admin_user, target_user_id, new_pwd)   → (bool, str)
"""
 
import uuid
import secrets
from datetime import datetime, timedelta
 
import core.db as db
import core.objects as objects
from core.crypto import hash_password, verify_password
 
# Durée de vie d'une session
SESSION_DURATION_MINUTES = 30
 
# Caractères spéciaux acceptés pour les mots de passe
_SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  VALIDATION MOT DE PASSE
# ═══════════════════════════════════════════════════════════════════════════════
 
def _validate_password(password: str) -> tuple[bool, str]:
    """
    Vérifie la politique de sécurité du mot de passe.
    Retourne (True, "") si valide, (False, message) sinon.
    """
    if len(password) < 6:
        return False, "Le mot de passe doit contenir au moins 6 caractères."
    if not any(c.isupper() for c in password):
        return False, "Le mot de passe doit contenir au moins une majuscule."
    if not any(c.islower() for c in password):
        return False, "Le mot de passe doit contenir au moins une minuscule."
    if not any(c.isdigit() for c in password):
        return False, "Le mot de passe doit contenir au moins un chiffre."
    if not any(c in _SPECIAL_CHARS for c in password):
        return False, "Le mot de passe doit contenir au moins un caractère spécial."
    return True, ""
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  INSCRIPTION
# ═══════════════════════════════════════════════════════════════════════════════
 
def register(username: str, password: str, confirm_password: str) -> tuple[bool, str]:
    """
    Inscrit un nouvel utilisateur.
 
    Règle du premier utilisateur :
        Si la table Users est vide au moment de l'inscription,
        le compte créé reçoit automatiquement le rôle 'admin'.
        Tous les suivants sont 'user'.
 
    Retourne (True, message_succès) ou (False, message_erreur).
    """
    username = username.strip().lower()
 
    # --- Validation username ---
    if not username:
        return False, "Le nom d'utilisateur ne peut pas être vide."
    if len(username) < 3:
        return False, "Le nom d'utilisateur doit contenir au moins 3 caractères."
 
    # --- Validation mot de passe ---
    if not password.strip():
        return False, "Le mot de passe ne peut pas être vide."
    ok, msg = _validate_password(password)
    if not ok:
        return False, msg
 
    # --- Confirmation ---
    if password != confirm_password:
        return False, "Les mots de passe ne correspondent pas."
 
    # --- Unicité ---
    if db.user_exists(username):
        return False, "Ce nom d'utilisateur est déjà pris."
 
    # --- Rôle : premier utilisateur = admin ---
    existing_users = db.list_users()
    role = "admin" if len(existing_users) == 0 else "user"
 
    # --- Hash du mot de passe ---
    user_id            = str(uuid.uuid4())
    salt               = secrets.token_bytes(32)
    pwd_hash, salt_hex = hash_password(password, salt)
 
    # --- Insertion en base ---
    ok, msg = db.create_user(
        user_id       = user_id,
        username      = username,
        password_hash = pwd_hash,
        salt          = salt_hex,
        role          = role,
    )
    if not ok:
        return False, msg
 
    # --- Log ---
    role_label = " (admin)" if role == "admin" else ""
    db.create_log(user_id, "register", f"Nouvel utilisateur{role_label} : {username}")
 
    return True, (
        f"Compte '{username}' créé avec succès"
        + (" — vous êtes administrateur." if role == "admin" else ".")
        + " Vous pouvez maintenant vous connecter."
    )
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  CONNEXION
# ═══════════════════════════════════════════════════════════════════════════════
 
def login(username: str, password: str) -> tuple[bool, objects.User | str]:
    """
    Authentifie un utilisateur.
 
    Retourne (True, objects.User) ou (False, message_erreur).
    """
    username = username.strip().lower()
 
    if not username:
        return False, "Le nom d'utilisateur ne peut pas être vide."
    if not password.strip():
        return False, "Le mot de passe ne peut pas être vide."
 
    user_row = db.get_user_by_username(username)
 
    # Message volontairement générique (ne révèle pas si le username existe)
    if user_row is None:
        return False, "Nom d'utilisateur ou mot de passe incorrect."
 
    if not verify_password(password, user_row["password_hash"], user_row["salt"]):
        db.create_log(user_row["user_id"], "login_failed",
                      f"Tentative échouée : {username}")
        return False, "Nom d'utilisateur ou mot de passe incorrect."
 
    current_user = objects.User(
        user_id       = user_row["user_id"],
        username      = user_row["username"],
        password_hash = user_row["password_hash"],
        salt          = user_row["salt"],
        role          = user_row["role"],
        created_at    = user_row["created_at"],
        updated_at    = user_row["updated_at"],
    )
 
    db.create_log(current_user.user_id, "login", f"Connexion : {username}")
    return True, current_user
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  SESSION
# ═══════════════════════════════════════════════════════════════════════════════
 
def create_user_session(user_id: str) -> objects.Session:
    """
    Crée une session pour l'utilisateur connecté.
    Supprime toute session existante (une seule active à la fois).
    Lève RuntimeError si la base échoue.
    """
    session_id  = secrets.token_hex(32)
    created_at  = datetime.now()
    expires_at  = created_at + timedelta(minutes=SESSION_DURATION_MINUTES)
    expires_str = expires_at.strftime("%Y-%m-%d %H:%M:%S")
 
    ok, msg = db.create_session(session_id, user_id, expires_str)
    if not ok:
        raise RuntimeError(f"Impossible de créer la session : {msg}")
 
    return objects.Session(
        session_id = session_id,
        user_id    = user_id,
        created_at = created_at,
        expires_at = expires_at,
    )
 
 
def logout(session_id: str, user_id: str) -> None:
    """Supprime la session et enregistre le log de déconnexion."""
    db.delete_session(session_id)
    db.create_log(user_id, "logout", "Déconnexion")
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  MODIFICATION DE COMPTE
# ═══════════════════════════════════════════════════════════════════════════════
 
def change_username(
    user_id: str,
    new_username: str,
    current_password: str,
) -> tuple[bool, str]:
    """
    Change le nom d'utilisateur après vérification du mot de passe actuel.
    """
    new_username = new_username.strip().lower()
 
    if not new_username:
        return False, "Le nouveau nom ne peut pas être vide."
    if len(new_username) < 3:
        return False, "Le nom doit contenir au moins 3 caractères."
 
    user_row = db.get_user_by_id(user_id)
    if user_row is None:
        return False, "Utilisateur introuvable."
    if not verify_password(current_password, user_row["password_hash"], user_row["salt"]):
        return False, "Mot de passe incorrect."
 
    old_username = user_row["username"]
    if new_username == old_username:
        return False, "Le nouveau nom est identique à l'ancien."
 
    ok, msg = db.update_username(user_id, new_username)
    if not ok:
        return False, msg
 
    db.create_log(user_id, "change_username", f"{old_username} → {new_username}")
    return True, f"Nom d'utilisateur changé en '{new_username}'."
 
 
def change_password(
    user_id: str,
    old_password: str,
    new_password: str,
    confirm_new_password: str,
) -> tuple[bool, str]:
    """
    Change le mot de passe après vérification de l'ancien.
    """
    user_row = db.get_user_by_id(user_id)
    if user_row is None:
        return False, "Utilisateur introuvable."
 
    if not verify_password(old_password, user_row["password_hash"], user_row["salt"]):
        return False, "Ancien mot de passe incorrect."
 
    ok, msg = _validate_password(new_password)
    if not ok:
        return False, msg
 
    if new_password != confirm_new_password:
        return False, "Les nouveaux mots de passe ne correspondent pas."
 
    if old_password == new_password:
        return False, "Le nouveau mot de passe doit être différent de l'ancien."
 
    salt               = secrets.token_bytes(32)
    new_hash, salt_hex = hash_password(new_password, salt)
 
    ok, msg = db.update_password(user_id, new_hash, salt_hex)
    if not ok:
        return False, msg
 
    db.create_log(user_id, "change_password", "Mot de passe modifié")
    return True, "Mot de passe mis à jour avec succès."
 
 
# ═══════════════════════════════════════════════════════════════════════════════
#  GESTION ADMIN
# ═══════════════════════════════════════════════════════════════════════════════
 
def admin_delete_user(
    admin_user: objects.User,
    target_user_id: str,
) -> tuple[bool, str]:
    """
    Supprime un utilisateur et ses fichiers physiques.
    Réservé à l'admin.
    """
    if admin_user.role != "admin":
        return False, "Accès refusé."
    if target_user_id == admin_user.user_id:
        return False, "Vous ne pouvez pas supprimer votre propre compte."
 
    target = db.get_user_by_id(target_user_id)
    if target is None:
        return False, "Utilisateur introuvable."
 
    # Suppression des fichiers physiques
    from pathlib import Path
    import shutil
    storage_dir = Path("storage") / "users" / target_user_id
    if storage_dir.exists():
        shutil.rmtree(storage_dir)
 
    # Suppression en base (CASCADE : sessions + fichiers supprimés aussi)
    ok, msg = db.delete_user(target_user_id)
    if not ok:
        return False, msg
 
    db.create_log(
        admin_user.user_id, "delete_user",
        f"Admin a supprimé : {target['username']} ({target_user_id})"
    )
    return True, f"Utilisateur '{target['username']}' supprimé."
 
 
def admin_reset_password(
    admin_user: objects.User,
    target_user_id: str,
    new_password: str,
) -> tuple[bool, str]:
    """
    Réinitialise le mot de passe d'un utilisateur sans connaître l'ancien.
    Réservé à l'admin.
    """
    if admin_user.role != "admin":
        return False, "Accès refusé."
 
    ok, msg = _validate_password(new_password)
    if not ok:
        return False, msg
 
    target = db.get_user_by_id(target_user_id)
    if target is None:
        return False, "Utilisateur introuvable."
 
    salt               = secrets.token_bytes(32)
    new_hash, salt_hex = hash_password(new_password, salt)
 
    ok, msg = db.update_password(target_user_id, new_hash, salt_hex)
    if not ok:
        return False, msg
 
    db.create_log(
        admin_user.user_id, "change_password",
        f"Admin a réinitialisé le mot de passe de : {target['username']}"
    )
    return True, f"Mot de passe de '{target['username']}' réinitialisé."

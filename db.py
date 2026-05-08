"""
db.py — Couche d'accès à la base de données
Toutes les interactions SQLite passent par ce fichier.
"""

import sqlite3
import os
from datetime import datetime 

DB_PATH     = "User_Management.db"
SCHEMA_PATH = "schema.sql"


# ============================================================
#  CONNEXION
# ============================================================

def get_connection() -> sqlite3.Connection:
    """
    Ouvre et retourne une connexion SQLite configurée.
    - row_factory  : les résultats sont des dicts  {colonne: valeur}
    - foreign_keys : ON  (cascade delete sessions si user supprimé)
    Chaque appelant est responsable de fermer la connexion (ou utiliser with).
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row       # accès par nom de colonne : row["username"]
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """
    Initialise la base de données en exécutant schema.sql.
    À appeler une seule fois au démarrage de l'application (dans main.py).
    Sans effet si les tables existent déjà (CREATE TABLE IF NOT EXISTS).
    """
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"schema.sql introuvable : {SCHEMA_PATH}")

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        sql = f.read()

    with get_connection() as conn:
        conn.executescript(sql)


# ============================================================
#  USERS  —  lecture
# ============================================================

def get_user_by_username(username: str) -> sqlite3.Row | None:
    """
    Retourne la ligne Users complète pour ce username, ou None.
    Usage :
        user = get_user_by_username("alice")
        if user:
            print(user["password_hash"])
    """
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM Users WHERE username = ?",
            (username.strip().lower(),)
        ).fetchone()


def get_user_by_id(user_id: str) -> sqlite3.Row | None:
    """Retourne la ligne Users pour cet user_id, ou None."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM Users WHERE user_id = ?",
            (user_id,)
        ).fetchone()


def user_exists(username: str) -> bool:
    """Vérifie si un username est déjà pris."""
    return get_user_by_username(username) is not None


def list_users() -> list[sqlite3.Row]:
    """
    Retourne tous les users (sans les hash/salt).
    Réservé à l'admin.
    """
    with get_connection() as conn:
        return conn.execute(
            "SELECT user_id, username, role, created_at, updated_at FROM Users"
        ).fetchall()


# ============================================================
#  USERS  —  écriture
# ============================================================

def create_user(
    user_id: str,
    username: str,
    password_hash: str,
    salt: str,
    role: str = "user",
    created_at: datetime | None = None,
    updated_at: datetime | None = None
) -> tuple[bool, str]:

    if created_at is None:
        created_at = datetime.now()

    if updated_at is None:
        updated_at = datetime.now()
    """
    Insère un nouvel utilisateur.
    Retourne (True, message) ou (False, message d'erreur).
    """
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO Users (user_id, username, password_hash, salt, role,created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (user_id, username.strip().lower(), password_hash, salt, role, created_at, updated_at)
            )
        return True, f"Utilisateur '{username}' créé."
    except sqlite3.IntegrityError:
        return False, "Ce nom d'utilisateur est déjà pris."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


def update_username(user_id: str, new_username: str) -> tuple[bool, str]:
    """Change le username d'un utilisateur (l'id ne change jamais)."""
    new_username = new_username.strip().lower()
    if user_exists(new_username):
        return False, "Ce nom d'utilisateur est déjà pris."
    try:
        with get_connection() as conn:
            conn.execute(
                "UPDATE Users SET username = ? WHERE user_id = ?",
                (new_username, user_id)
            )
        return True, "Nom d'utilisateur mis à jour."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


def update_password(user_id: str, new_hash: str, new_salt: str) -> tuple[bool, str]:
    """Met à jour le hash et le salt du mot de passe."""
    try:
        with get_connection() as conn:
            conn.execute(
                "UPDATE Users SET password_hash = ?, salt = ? WHERE user_id = ?",
                (new_hash, new_salt, user_id)
            )
        return True, "Mot de passe mis à jour."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


# ============================================================
#  SESSIONS  —  lecture
# ============================================================

def get_session(session_id: str) -> sqlite3.Row | None:
    """
    Retourne la session si elle existe ET n'est pas expirée.
    Retourne None si introuvable ou expirée.
    """
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT * FROM Sessions
            WHERE session_id = ?
              AND expires_at > datetime('now')
            """,
            (session_id,)
        ).fetchone()


def get_active_session_for_user(user_id: str) -> sqlite3.Row | None:
    """Retourne la session active d'un user, ou None."""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT * FROM Sessions
            WHERE user_id = ?
              AND expires_at > datetime('now')
            """,
            (user_id,)
        ).fetchone()


# ============================================================
#  SESSIONS  —  écriture
# ============================================================

def create_session(
    session_id: str,
    user_id: str,
    expires_at: str          # ISO-8601 : "2025-05-10 14:30:00"
) -> tuple[bool, str]:
    """
    Crée une nouvelle session.
    Supprime d'abord toute session existante pour ce user (une seule session active).
    """
    try:
        with get_connection() as conn:
            # Supprimer l'ancienne session (design : une session par user)
            conn.execute("DELETE FROM Sessions WHERE user_id = ?", (user_id,))
            conn.execute(
                """
                INSERT INTO Sessions (session_id, user_id, expires_at)
                VALUES (?, ?, ?)
                """,
                (session_id, user_id, expires_at)
            )
        return True, "Session créée."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


def delete_session(session_id: str) -> None:
    """Supprime une session (logout)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM Sessions WHERE session_id = ?", (session_id,))


def delete_expired_sessions() -> int:
    """
    Supprime toutes les sessions expirées.
    Retourne le nombre de sessions supprimées.
    À appeler périodiquement (ex: au démarrage, ou après chaque login).
    """
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM Sessions WHERE expires_at <= datetime('now')"
        )
        return cursor.rowcount

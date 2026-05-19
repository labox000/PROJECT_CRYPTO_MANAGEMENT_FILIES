"""
db.py — Couche d'accès à la base de données.
Toutes les interactions SQLite passent par ce fichier.

PART 1 : Connexion & initialisation
PART 2 : Gestion des utilisateurs  (lecture / écriture)
PART 3 : Sessions
PART 4 : Fichiers
PART 5 : Logs
"""

import sqlite3
import os
import secrets
from datetime import datetime

DB_PATH     = "User_Management.db"
SCHEMA_PATH = "schema.sql"

# ═══════════════════════════════════════════════════════════════════════════════
#  PART 1 — CONNEXION & INITIALISATION
# ═══════════════════════════════════════════════════════════════════════════════

def get_connection() -> sqlite3.Connection:
    """
    Ouvre et retourne une connexion SQLite configurée.
    - row_factory  : résultats accessibles par nom de colonne (row["username"])
    - foreign_keys : ON  (cascade delete sessions/fichiers si user supprimé)
    - WAL          : meilleures performances en lecture concurrente
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn


def init_db() -> None:
    """
    Initialise la base de données en exécutant schema.sql.
    Sans effet si les tables existent déjà (CREATE TABLE IF NOT EXISTS).

    Le premier utilisateur qui s'inscrit via register() devient automatiquement
    admin — aucun compte n'est hardcodé ici.

    À appeler une seule fois au démarrage dans main.py.
    """
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"schema.sql introuvable : {SCHEMA_PATH}")

    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        sql = f.read()

    with get_connection() as conn:
        conn.executescript(sql)


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 2 — UTILISATEURS : lecture
# ═══════════════════════════════════════════════════════════════════════════════

def get_user_by_username(username: str) -> sqlite3.Row | None:
    """Retourne la ligne Users complète pour ce username, ou None."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM Users WHERE username = ?",
            (username.strip().lower(),)
        ).fetchone()


def get_user_by_id(user_id: str) -> sqlite3.Row | None:
    """Retourne la ligne Users complète pour cet user_id, ou None."""
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
    Retourne tous les utilisateurs SANS hash ni salt.
    Usage : affichage standard, menu utilisateur.
    """
    with get_connection() as conn:
        return conn.execute(
            "SELECT user_id, username, role, created_at, updated_at FROM Users"
        ).fetchall()


def list_users_admin() -> list[sqlite3.Row]:
    """
    Retourne tous les utilisateurs AVEC hash et salt.
    Réservé à l'admin — affiche les données sensibles.
    """
    with get_connection() as conn:
        return conn.execute(
            "SELECT user_id, username, role, password_hash, salt, created_at, updated_at FROM Users"
        ).fetchall()


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 2 — UTILISATEURS : écriture
# ═══════════════════════════════════════════════════════════════════════════════

def create_user(
    user_id: str,
    username: str,
    password_hash: str,
    salt: str,
    role: str = "user",
    created_at: datetime | None = None,
    updated_at: datetime | None = None,
) -> tuple[bool, str]:
    """
    Insère un nouvel utilisateur.
    Retourne (True, message) ou (False, message d'erreur).
    """
    created_at = created_at or datetime.now()
    updated_at = updated_at or datetime.now()

    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO Users (user_id, username, password_hash, salt, role, created_at, updated_at)
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


def delete_user(user_id: str) -> tuple[bool, str]:
    """
    Supprime un utilisateur et, par CASCADE, ses sessions et ses fichiers en base.
    Les fichiers physiques dans storage/ doivent être supprimés séparément
    (géré dans files.py avant d'appeler cette fonction).
    Ne peut pas supprimer le compte admin principal.
    """
    if user_id == "00000000-0000-0000-0000-000000000001":
        return False, "Impossible de supprimer le compte admin principal."
    try:
        with get_connection() as conn:
            cursor = conn.execute("DELETE FROM Users WHERE user_id = ?", (user_id,))
            if cursor.rowcount == 0:
                return False, "Utilisateur introuvable."
        return True, "Utilisateur supprimé."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 2 — PERMISSIONS
# ═══════════════════════════════════════════════════════════════════════════════

def is_admin(user: sqlite3.Row) -> bool:
    """Retourne True si l'utilisateur a le rôle admin."""
    return user["role"] == "admin"


def require_admin(user: sqlite3.Row) -> None:
    """Lève PermissionError si l'utilisateur n'est pas admin."""
    if user["role"] != "admin":
        raise PermissionError("Accès réservé à l'administrateur.")


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 3 — SESSIONS : lecture
# ═══════════════════════════════════════════════════════════════════════════════

def get_session(session_id: str) -> sqlite3.Row | None:
    """
    Retourne la session si elle existe ET n'est pas expirée.
    Retourne None sinon.
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


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 3 — SESSIONS : écriture
# ═══════════════════════════════════════════════════════════════════════════════

def create_session(
    session_id: str,
    user_id: str,
    expires_at: str,
) -> tuple[bool, str]:
    """
    Crée une nouvelle session.
    Supprime d'abord toute session existante (une seule session active par user).
    expires_at : string ISO-8601 ex "2025-05-10 14:30:00"
    """
    try:
        with get_connection() as conn:
            conn.execute("DELETE FROM Sessions WHERE user_id = ?", (user_id,))
            conn.execute(
                "INSERT INTO Sessions (session_id, user_id, expires_at) VALUES (?, ?, ?)",
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
    À appeler au démarrage de l'application.
    """
    with get_connection() as conn:
        cursor = conn.execute(
            "DELETE FROM Sessions WHERE expires_at <= datetime('now')"
        )
        return cursor.rowcount


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 4 — FICHIERS : lecture
# ═══════════════════════════════════════════════════════════════════════════════

def get_file(file_id: str) -> sqlite3.Row | None:
    """Retourne un fichier par son ID, ou None."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM Files WHERE file_id = ?",
            (file_id,)
        ).fetchone()


def get_file_by_name(owner_id: str, filename: str) -> sqlite3.Row | None:
    """Retourne le fichier d'un user par son nom, ou None."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM Files WHERE owner_id = ? AND filename = ?",
            (owner_id, filename)
        ).fetchone()


def list_user_files(owner_id: str) -> list[sqlite3.Row]:
    """Retourne tous les fichiers d'un utilisateur."""
    with get_connection() as conn:
        return conn.execute(
            "SELECT * FROM Files WHERE owner_id = ?",
            (owner_id,)
        ).fetchall()


def list_all_files() -> list[sqlite3.Row]:
    """Retourne tous les fichiers de tous les users. Réservé admin."""
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT f.*, u.username
            FROM Files f
            JOIN Users u ON f.owner_id = u.user_id
            ORDER BY u.username, f.filename
            """
        ).fetchall()


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 4 — FICHIERS : écriture
# ═══════════════════════════════════════════════════════════════════════════════

def create_file(
    file_id: str,
    owner_id: str,
    filename: str,
    crypto_mode: str,
    crypto_meta: str,       # json.dumps({"key": ..., "iv": ...})
    stored_path: str,
    integrity_hash: str,    # SHA-256 du contenu AVANT chiffrement
) -> tuple[bool, str]:
    """Enregistre un fichier en base après chiffrement."""
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO Files
                    (file_id, owner_id, filename, crypto_mode, crypto_meta, stored_path, integrity_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (file_id, owner_id, filename, crypto_mode, crypto_meta, stored_path, integrity_hash)
            )
        return True, f"Fichier '{filename}' enregistré."
    except sqlite3.IntegrityError:
        return False, f"Vous avez déjà un fichier nommé '{filename}'."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


def update_file(
    file_id: str,
    filename: str,
    crypto_mode: str,
    crypto_meta: str,
    stored_path: str,
    integrity_hash: str,
) -> tuple[bool, str]:
    """
    Met à jour les métadonnées d'un fichier après modification.
    Le trigger SQL updated_at se charge de mettre à jour la date automatiquement.
    """
    try:
        with get_connection() as conn:
            conn.execute(
                """
                UPDATE Files
                SET filename       = ?,
                    crypto_mode    = ?,
                    crypto_meta    = ?,
                    stored_path    = ?,
                    integrity_hash = ?
                WHERE file_id = ?
                """,
                (filename, crypto_mode, crypto_meta, stored_path, integrity_hash, file_id)
            )
        return True, f"Fichier '{filename}' mis à jour."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


def delete_file(file_id: str) -> tuple[bool, str]:
    """Supprime l'entrée d'un fichier en base."""
    try:
        with get_connection() as conn:
            conn.execute("DELETE FROM Files WHERE file_id = ?", (file_id,))
        return True, "Fichier supprimé."
    except sqlite3.Error as e:
        return False, f"Erreur base de données : {e}"


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 5 — LOGS : écriture
# ═══════════════════════════════════════════════════════════════════════════════

def create_log(
    user_id: str,
    action: str,
    detail: str = "",
) -> None:
    """
    Enregistre une action dans les logs.
    Silencieux en cas d'erreur (les logs ne doivent jamais bloquer l'app).

    Actions attendues :
        register, login, logout, login_failed,
        change_username, change_password,
        add_file, delete_file, modify_file, verify_integrity
    """
    import uuid
    log_id = str(uuid.uuid4())
    try:
        with get_connection() as conn:
            conn.execute(
                "INSERT INTO Logs (log_id, user_id, action, detail) VALUES (?, ?, ?, ?)",
                (log_id, user_id, action, detail)
            )
    except sqlite3.Error:
        pass  # Les logs ne bloquent jamais l'application


# ═══════════════════════════════════════════════════════════════════════════════
#  PART 5 — LOGS : lecture (réservé admin)
# ═══════════════════════════════════════════════════════════════════════════════

def get_all_logs() -> list[sqlite3.Row]:
    """
    Retourne tous les logs avec date, user_id, username, prénom et action.
    Triés du plus récent au plus ancien.
    Réservé à l'admin.
    """
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT
                l.log_id,
                l.created_at,
                l.action,
                l.detail,
                u.user_id,
                u.username
            FROM Logs l
            JOIN Users u ON l.user_id = u.user_id
            ORDER BY l.created_at DESC
            """
        ).fetchall()


def get_logs_by_user_id(user_id: str) -> list[sqlite3.Row]:
    """
    Retourne tous les logs d'un utilisateur précis (recherche par user_id).
    Réservé à l'admin.
    """
    with get_connection() as conn:
        return conn.execute(
            """
            SELECT
                l.log_id,
                l.created_at,
                l.action,
                l.detail,
                u.user_id,
                u.username
            FROM Logs l
            JOIN Users u ON l.user_id = u.user_id
            WHERE l.user_id = ?
            ORDER BY l.created_at DESC
            """,
            (user_id,)
        ).fetchall()


def get_logs_by_username(username: str) -> list[sqlite3.Row]:
    """
    Retourne tous les logs d'un utilisateur recherché par son username.
    Réservé à l'admin.
    """
    user = get_user_by_username(username)
    if user is None:
        return []
    return get_logs_by_user_id(user["user_id"])


def search_logs(query: str) -> list[sqlite3.Row]:
    """
    Recherche dans les logs par username OU user_id.
    L'admin peut taper n'importe lequel des deux.
    Retourne une liste vide si rien trouvé.
    """
    # Essai par user_id exact d'abord
    results = get_logs_by_user_id(query)
    if results:
        return results
    # Sinon par username (insensible à la casse)
    return get_logs_by_username(query)
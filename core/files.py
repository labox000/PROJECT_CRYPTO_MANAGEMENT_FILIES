"""
files.py — Gestion des fichiers utilisateurs.
Chiffrement, déchiffrement, intégrité, contrôle d'accès.


  -j'ai modifié  : open_file() déchiffrait sans contrôle d'accès. :
      * Propriétaire --> contenu en clair.
      * Non-propriétaire -->contenu chiffré affiché tel quel (accès refusé au déchiffrement).
  - AJOUT : vérification d'intégrité (hash SHA-256) à chaque ouverture.
  - AJOUT : hash stocké à la création, recalculé après chaque modification.
"""

import json
import uuid
import secrets
from pathlib import Path

import db
from crypto import sha256, encrypt_file, decrypt_file, SYMMETRIC_ALGOS
from objects import User

STORAGE_ROOT = Path("storage") / "users"


# ─── UTILITAIRE HASH ─────────────────────────────────────────────────────────

def compute_hash(data: bytes) -> str:
    """Calcule le SHA-256 (maison) d'un bloc de données brutes."""
    return sha256(data)


# ─── AJOUT D'UN FICHIER ───────────────────────────────────────────────────────

def add_file(
    source_path: str | Path,
    current_user: User,
    mode: str,
    meta: dict,
) -> Path:
    """
    Pipeline complet :
      1. Lecture du fichier source
      2. Calcul du hash du contenu brut
      3. Chiffrement selon l'algo choisi
      4. Sauvegarde physique dans storage/users/<user_id>/
      5. Enregistrement en base (avec hash et métadonnées crypto)

    Args:
        source_path  : chemin vers le fichier fourni par l'utilisateur
        current_user : objet User connecté
        mode         : clé algo (ex: "XOR", "César", "DES"…)
        meta         : dict contenant la clé/shift/iv selon l'algo

    Returns:
        Path du fichier chiffré.
    Raises:
        FileNotFoundError, FileExistsError, RuntimeError
    """
    source = Path(source_path).resolve()
    if not source.exists() or not source.is_file():
        raise FileNotFoundError(f"Fichier introuvable : '{source}'")

    if db.get_file_by_name(current_user.user_id, source.name):
        raise FileExistsError(
            f"Vous avez déjà un fichier nommé '{source.name}'. "
            "Supprimez-le ou renommez le fichier source."
        )

    # Dossier de stockage propre à l'utilisateur
    user_dir = STORAGE_ROOT / current_user.user_id
    user_dir.mkdir(parents=True, exist_ok=True)
    dest = user_dir / source.name

    raw_data = source.read_bytes()

    # Hash du contenu BRUT (avant chiffrement)
    file_hash = compute_hash(raw_data)

    # Chiffrement
    encrypted_data = encrypt_file(raw_data, mode, meta)

    # Sauvegarde physique
    dest.write_bytes(encrypted_data)

    # Enregistrement en base
    ok, msg = db.create_file(
        file_id     = str(uuid.uuid4()),
        owner_id    = current_user.user_id,
        filename    = source.name,
        file_hash   = file_hash,
        crypto_mode = mode,
        crypto_meta = json.dumps(meta),
        stored_path = str(dest),
    )

    if not ok:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"Erreur d'enregistrement : {msg}")

    return dest


# ─── OUVERTURE / LECTURE ──────────────────────────────────────────────────────

def open_file(
    filename: str,
    owner_id: str,
    current_user: User,
) -> tuple[bytes, bool, bool]:
    """
    Ouvre un fichier et applique le contrôle d'accès.

    Retourne (contenu, is_decrypted, integrity_ok) :
      - contenu       : bytes en clair (si propriétaire) ou bytes chiffrés
      - is_decrypted  : True si le propriétaire a reçu le contenu déchiffré
      - integrity_ok  : True si le hash recalculé correspond au hash stocké

    FIX : la version originale déchiffrait sans aucun contrôle d'accès.
    """
    file_row = db.get_file_by_name(owner_id, filename)
    if not file_row:
        raise FileNotFoundError(f"Fichier '{filename}' introuvable.")

    stored_path = Path(file_row["stored_path"])
    if not stored_path.exists():
        raise FileNotFoundError(f"Fichier physique manquant : {stored_path}")

    encrypted = stored_path.read_bytes()
    meta       = json.loads(file_row["crypto_meta"])
    mode       = file_row["crypto_mode"]

    is_owner = (file_row["owner_id"] == current_user.user_id)

    if is_owner:
        # Déchiffrement
        raw_data = decrypt_file(encrypted, mode, meta)

        # Vérification d'intégrité (hash du contenu brut)
        current_hash  = compute_hash(raw_data)
        stored_hash   = file_row["file_hash"]
        integrity_ok  = (current_hash == stored_hash)

        return raw_data, True, integrity_ok
    else:
        # Non-propriétaire : accès autorisé mais contenu reste chiffré
        return encrypted, False, True  # pas de vérification d'intégrité ici


# ─── SUPPRESSION ──────────────────────────────────────────────────────────────

def delete_file(filename: str, current_user: User) -> None:
    """
    Supprime un fichier (physique + base).
    Seul le propriétaire peut supprimer.
    """
    file_row = db.get_file_by_name(current_user.user_id, filename)
    if not file_row:
        raise FileNotFoundError(f"'{filename}' introuvable dans votre espace.")

    if file_row["owner_id"] != current_user.user_id:
        raise PermissionError("Vous ne pouvez supprimer que vos propres fichiers.")

    path = Path(file_row["stored_path"])
    path.unlink(missing_ok=True)

    db.delete_file(file_row["file_id"])


# ─── LISTAGE ──────────────────────────────────────────────────────────────────

def list_files(owner_id: str, current_user: User) -> list:
    """
    Retourne les fichiers d'un utilisateur.
    Tout le monde peut lister, le déchiffrement est réservé au propriétaire.
    """
    return db.list_user_files(owner_id)


# ─── TABLEAU DE BORD  ────────────────────────────────

def dashboard_files(current_user: User) -> None:
    """
    Affiche le tableau de bord de l'utilisateur avec statut d'intégrité
    de chacun de ses fichiers.
    """
    files = db.list_user_files(current_user.user_id)
    if not files:
        print("\n  Aucun fichier dans votre espace.")
        return

    print(f"\n  {'Fichier':<25} {'Algo':<12} {'Intégrité':<12} {'Modifié le'}")
    print("  " + "─" * 70)

    for f in files:
        stored_path = Path(f["stored_path"])
        integrity   = "N/A"

        if stored_path.exists():
            try:
                encrypted    = stored_path.read_bytes()
                meta         = json.loads(f["crypto_meta"])
                raw_data     = decrypt_file(encrypted, f["crypto_mode"], meta)
                current_hash = compute_hash(raw_data)
                integrity    = "✅ OK" if current_hash == f["file_hash"] else "❌ MODIFIÉ"
            except Exception:
                integrity = "  Erreur"
        else:
            integrity = "  Manquant"

        updated = f["updated_at"][:16] if f["updated_at"] else "?"
        print(f"  {f['filename']:<25} {f['crypto_mode']:<12} {integrity:<12} {updated}")

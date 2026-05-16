"""
files.py — Gestion des fichiers utilisateurs
Lecture, chiffrement, sauvegarde, permissions.
"""

import json
import uuid
import shutil
from pathlib import Path

from .crypto import encrypt, decrypt, prompt_crypto_mode
from .db import (
    create_file, delete_file as db_delete_file,
    get_file, get_file_by_name,
    list_user_files, list_all_files,
    get_user_by_id, is_admin
)

COPY_MODE    = True   # False => déplace l'original au lieu de le copier
STORAGE_ROOT = Path(__file__).parent.parent / "storage" / "users"


def _assert_owner(file_row, current_user_id: str) -> None:
    """Lève PermissionError si current_user n'est pas le propriétaire."""
    if file_row["owner_id"] != current_user_id:
        raise PermissionError("Vous ne pouvez pas modifier les fichiers des autres utilisateurs.")



def add_file(source_path: str | Path, current_user_id: str) -> Path:
    """
    Pipeline complet : lecture → chiffrement → sauvegarde physique → enregistrement en base.

    Args:
        source_path     : chemin vers le fichier fourni par l'utilisateur
        current_user_id : user_id de l'utilisateur connecté

    Returns:
        Path du fichier chiffré dans storage/
    """
    source = Path(source_path).resolve()

    if not source.exists():
        raise FileNotFoundError(f"Fichier introuvable : '{source}'")
    if not source.is_file():
        raise ValueError(f"'{source}' n'est pas un fichier.")

    # Vérifier doublon en base avant de faire quoi que ce soit
    if get_file_by_name(current_user_id, source.name):
        raise FileExistsError(
            f"Vous avez déjà un fichier nommé '{source.name}'. "
            "Supprimez-le ou renommez le fichier source."
        )

    # Dossier de destination
    user_dir = STORAGE_ROOT / current_user_id
    user_dir.mkdir(parents=True, exist_ok=True)
    dest = user_dir / source.name

    #1. Lecture 
    raw_data = source.read_bytes()

    #2. Choix du mode de chiffrement 
    mode_key = prompt_crypto_mode()

    #3. Chiffrement 
    encrypted_data, metadata = encrypt(raw_data, mode_key)

    #4. Sauvegarde physique 
    dest.write_bytes(encrypted_data)

    if not COPY_MODE:
        source.unlink()   # supprime l'original si COPY_MODE désactivé

    #5. Enregistrement en base 
    ok, msg = create_file(
        file_id     = str(uuid.uuid4()),
        owner_id    = current_user_id,
        filename    = source.name,
        crypto_mode = mode_key,
        crypto_meta = json.dumps(metadata),
        stored_path = str(dest),
    )

    if not ok:
        dest.unlink()    # rollback physique si la base a échoué
        raise RuntimeError(f"Erreur enregistrement : {msg}")

    print(f"[OK] '{source.name}' chiffré et enregistré.")
    return dest


def open_file(filename: str, owner_id: str, current_user_id: str) -> bytes:
    """
    Déchiffre et retourne le contenu d'un fichier.
    Accessible par tous les utilisateurs (lecture seule pour les non-propriétaires).
    """
    file_row = get_file_by_name(owner_id, filename)
    if not file_row:
        raise FileNotFoundError(f"'{filename}' introuvable.")

    encrypted = Path(file_row["stored_path"]).read_bytes()
    metadata  = json.loads(file_row["crypto_meta"])

    return decrypt(encrypted, metadata)


def delete_file(filename: str, current_user_id: str) -> None:
    """
    Supprime un fichier (physique + base).
    Seul le propriétaire peut supprimer.
    """
    file_row = get_file_by_name(current_user_id, filename)
    if not file_row:
        raise FileNotFoundError(f"'{filename}' introuvable dans votre espace.")

    _assert_owner(file_row, current_user_id)

    # Suppression physique
    path = Path(file_row["stored_path"])
    if path.exists():
        path.unlink()

    # Suppression en base
    db_delete_file(file_row["file_id"])
    print(f"[OK] '{filename}' supprimé.")



def list_files(owner_id: str, current_user_id: str) -> None:
    """
    Affiche les fichiers d'un utilisateur.
    Tout le monde peut lister, mais l'accès en écriture est réservé au propriétaire.
    """
    files = list_user_files(owner_id)
    if not files:
        print("Aucun fichier.")
        return

    is_owner = (owner_id == current_user_id)
    print(f"\n── Fichiers ({'vos fichiers' if is_owner else 'lecture seule'}) ──")
    for f in files:
        acces = "owner" if is_owner else "lecture"
        print(f"  [{acces}] {f['filename']}  —  {f['crypto_mode']}  —  {f['created_at']}")

"""
files.py — Gestion des fichiers utilisateurs.
Lecture, chiffrement, modification, suppression, vérification d'intégrité.

Fonctions publiques :
    add_file(source_path, current_user_id)              → Path
    open_file(filename, owner_id, current_user_id)      → bytes
    modify_file(filename, current_user_id)              → Path
    delete_file(filename, current_user_id)              → None
    verify_integrity(filename, current_user_id)         → bool
    list_files(owner_id, current_user_id)               → None
"""

import json
import uuid
import shutil
from pathlib import Path

import core.db as db
from core.crypto import (
    encrypt, decrypt,
    prompt_crypto_mode,
    compute_integrity_hash,
    verify_integrity as crypto_verify_integrity,
)

# ── Configuration ──────────────────────────────────────────────────────────────
STORAGE_ROOT = Path(__file__).parent.parent / "storage" / "users"


# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITAIRES INTERNES
# ═══════════════════════════════════════════════════════════════════════════════

def _assert_owner(file_row: db.sqlite3.Row, current_user_id: str) -> None:
    """Lève PermissionError si current_user n'est pas le propriétaire du fichier."""
    if file_row["owner_id"] != current_user_id:
        raise PermissionError(
            "Vous ne pouvez pas modifier les fichiers d'un autre utilisateur."
        )


def _get_file_or_raise(owner_id: str, filename: str) -> db.sqlite3.Row:
    """
    Retourne la ligne Files pour (owner_id, filename).
    Lève FileNotFoundError si absent.
    """
    file_row = db.get_file_by_name(owner_id, filename)
    if not file_row:
        raise FileNotFoundError(
            f"Fichier '{filename}' introuvable dans votre espace."
        )
    return file_row


def _user_dir(user_id: str) -> Path:
    """Retourne (et crée si besoin) le dossier storage/users/<user_id>/."""
    d = STORAGE_ROOT / user_id
    d.mkdir(parents=True, exist_ok=True)
    return d


# ═══════════════════════════════════════════════════════════════════════════════
#  AJOUT D'UN FICHIER
# ═══════════════════════════════════════════════════════════════════════════════

def add_file(source_path: str | Path, current_user_id: str) -> Path:
    """
    Pipeline complet : lecture → hash d'intégrité → chiffrement → sauvegarde → base.

    Args:
        source_path     : chemin vers le fichier fourni par l'utilisateur
        current_user_id : user_id de l'utilisateur connecté

    Retourne le Path du fichier chiffré dans storage/.

    Le fichier original n'est JAMAIS supprimé : l'utilisateur garde sa copie
    et une copie chiffrée est créée dans storage/.
    """
    source = Path(source_path).resolve()

    if not source.exists():
        raise FileNotFoundError(f"Fichier introuvable : '{source}'")
    if not source.is_file():
        raise ValueError(f"'{source}' n'est pas un fichier valide.")

    # Vérifier doublon avant de faire quoi que ce soit
    if db.get_file_by_name(current_user_id, source.name):
        raise FileExistsError(
            f"Vous avez déjà un fichier nommé '{source.name}'. "
            "Supprimez-le ou renommez le fichier source."
        )

    # 1. Lecture du contenu brut
    raw_data = source.read_bytes()

    # 2. Hash d'intégrité AVANT chiffrement (Option A)
    integrity_hash = compute_integrity_hash(raw_data)

    # 3. Choix de l'algorithme par l'utilisateur
    mode_key = prompt_crypto_mode()

    # 4. Chiffrement
    encrypted_data, metadata = encrypt(raw_data, mode_key)

    # 5. Sauvegarde physique dans storage/users/<user_id>/
    dest = _user_dir(current_user_id) / source.name
    dest.write_bytes(encrypted_data)

    # 6. Enregistrement en base
    ok, msg = db.create_file(
        file_id        = str(uuid.uuid4()),
        owner_id       = current_user_id,
        filename       = source.name,
        crypto_mode    = mode_key,
        crypto_meta    = json.dumps(metadata),
        stored_path    = str(dest),
        integrity_hash = integrity_hash,
    )

    if not ok:
        dest.unlink(missing_ok=True)  # rollback physique
        raise RuntimeError(f"Erreur enregistrement en base : {msg}")

    # 7. Log
    db.create_log(current_user_id, "add_file", source.name)

    print(f"[OK] '{source.name}' chiffré ({mode_key}) et enregistré.")
    return dest


# ═══════════════════════════════════════════════════════════════════════════════
#  OUVERTURE / LECTURE D'UN FICHIER
# ═══════════════════════════════════════════════════════════════════════════════

def open_file(filename: str, current_user_id: str) -> bytes:
    """
    Déchiffre et retourne le contenu d'un fichier.
    Seul le propriétaire peut lire ses fichiers.

    Args:
        filename        : nom du fichier à ouvrir
        current_user_id : user_id de l'utilisateur connecté

    Retourne les bytes du contenu déchiffré.
    """
    file_row = _get_file_or_raise(current_user_id, filename)
    _assert_owner(file_row, current_user_id)

    encrypted = Path(file_row["stored_path"]).read_bytes()
    metadata  = json.loads(file_row["crypto_meta"])

    return decrypt(encrypted, metadata)


# ═══════════════════════════════════════════════════════════════════════════════
#  MODIFICATION D'UN FICHIER
# ═══════════════════════════════════════════════════════════════════════════════

def modify_file(filename: str, new_source_path: str | Path, current_user_id: str) -> Path:
    """
    Modifie un fichier existant dans l'application.

    Workflow :
      1. Vérifie que le fichier appartient à l'utilisateur
      2. Lit le nouveau contenu depuis new_source_path
      3. Demande si l'utilisateur veut modifier l'original (le fichier source)
         ou seulement la copie dans l'application
      4. Calcule le nouveau hash d'intégrité
      5. Demande l'algorithme de chiffrement (peut changer à chaque modification)
      6. Chiffre et écrase le fichier dans storage/
      7. Met à jour la base de données

    Args:
        filename        : nom du fichier à modifier (dans l'application)
        new_source_path : chemin vers le fichier contenant le nouveau contenu
        current_user_id : user_id de l'utilisateur connecté

    Retourne le Path du fichier chiffré mis à jour.
    """
    file_row = _get_file_or_raise(current_user_id, filename)
    _assert_owner(file_row, current_user_id)

    new_source = Path(new_source_path).resolve()
    if not new_source.exists():
        raise FileNotFoundError(f"Fichier source introuvable : '{new_source}'")
    if not new_source.is_file():
        raise ValueError(f"'{new_source}' n'est pas un fichier valide.")

    # 1. Lecture du nouveau contenu
    new_raw_data = new_source.read_bytes()

    # 2. Proposition de modifier l'original
    print(f"\n  Voulez-vous aussi remplacer le fichier original '{new_source}' ?")
    print("    1. Oui — écraser l'original avec le nouveau contenu")
    print("    2. Non — garder l'original intact (seule la copie dans l'app est modifiée)")
    choix = input("  Votre choix : ").strip()
    if choix == "1":
        original_path = Path(file_row["stored_path"]).parent.parent / filename
        if original_path.exists():
            original_path.write_bytes(new_raw_data)
            print(f"  [OK] Fichier original '{filename}' mis à jour.")
        else:
            print(f"  [INFO] Fichier original introuvable, seule la copie dans l'app sera modifiée.")

    # 3. Hash d'intégrité du nouveau contenu (AVANT chiffrement)
    new_integrity_hash = compute_integrity_hash(new_raw_data)

    # 4. Choix de l'algorithme (peut être différent de l'original)
    print(f"\n  Algorithme actuel : {file_row['crypto_mode']}")
    print("  Choisissez l'algorithme pour la nouvelle version :")
    mode_key = prompt_crypto_mode()

    # 5. Chiffrement du nouveau contenu
    encrypted_data, metadata = encrypt(new_raw_data, mode_key)

    # 6. Écrasement physique du fichier chiffré
    dest = Path(file_row["stored_path"])
    dest.write_bytes(encrypted_data)

    # 7. Mise à jour en base
    ok, msg = db.update_file(
        file_id        = file_row["file_id"],
        filename       = filename,
        crypto_mode    = mode_key,
        crypto_meta    = json.dumps(metadata),
        stored_path    = str(dest),
        integrity_hash = new_integrity_hash,
    )

    if not ok:
        raise RuntimeError(f"Erreur mise à jour en base : {msg}")

    # 8. Log
    db.create_log(current_user_id, "modify_file", filename)

    print(f"[OK] '{filename}' modifié et rechiffré ({mode_key}).")
    return dest


# ═══════════════════════════════════════════════════════════════════════════════
#  SUPPRESSION D'UN FICHIER
# ═══════════════════════════════════════════════════════════════════════════════

def delete_file(filename: str, current_user_id: str) -> None:
    """
    Supprime un fichier (physique + base de données).
    Seul le propriétaire peut supprimer ses fichiers.

    Args:
        filename        : nom du fichier à supprimer
        current_user_id : user_id de l'utilisateur connecté
    """
    file_row = _get_file_or_raise(current_user_id, filename)
    _assert_owner(file_row, current_user_id)

    # Suppression physique
    path = Path(file_row["stored_path"])
    path.unlink(missing_ok=True)

    # Suppression en base
    ok, msg = db.delete_file(file_row["file_id"])
    if not ok:
        raise RuntimeError(f"Erreur suppression en base : {msg}")

    # Log
    db.create_log(current_user_id, "delete_file", filename)

    print(f"[OK] '{filename}' supprimé.")


# ═══════════════════════════════════════════════════════════════════════════════
#  VÉRIFICATION D'INTÉGRITÉ
# ═══════════════════════════════════════════════════════════════════════════════

def verify_integrity(filename: str, current_user_id: str) -> bool:
    """
    Vérifie que le fichier n'a pas été corrompu ou modifié depuis son ajout.

    Mécanisme (Option A) :
      1. Déchiffre le fichier depuis storage/
      2. Calcule SHA-256 du contenu déchiffré
      3. Compare avec le hash stocké en base (calculé lors de l'ajout)

    Args:
        filename        : nom du fichier à vérifier
        current_user_id : user_id de l'utilisateur connecté

    Retourne True si intact, False si corrompu ou modifié.
    """
    file_row = _get_file_or_raise(current_user_id, filename)
    _assert_owner(file_row, current_user_id)

    stored_hash = file_row["integrity_hash"]

    # Déchiffrement
    try:
        encrypted = Path(file_row["stored_path"]).read_bytes()
        metadata  = json.loads(file_row["crypto_meta"])
        raw_data  = decrypt(encrypted, metadata)
    except Exception as e:
        print(f"[ERREUR] Impossible de déchiffrer '{filename}' : {e}")
        return False

    # Comparaison des hash
    intact = crypto_verify_integrity(raw_data, stored_hash)

    # Log avec résultat
    result_str = "OK - fichier intact" if intact else "ECHEC - fichier corrompu ou modifié"
    db.create_log(current_user_id, "verify_integrity", f"{filename} : {result_str}")

    if intact:
        print(f"[OK] '{filename}' — intégrité vérifiée, fichier intact.")
    else:
        print(f"[ALERTE] '{filename}' — intégrité compromise ! Le fichier a été modifié ou corrompu.")

    return intact


# ═══════════════════════════════════════════════════════════════════════════════
#  LISTAGE DES FICHIERS
# ═══════════════════════════════════════════════════════════════════════════════

def list_files(current_user_id: str) -> None:
    """
    Affiche les fichiers de l'utilisateur connecté.
    N'affiche PAS l'algorithme de chiffrement ni les métadonnées sensibles.

    Args:
        current_user_id : user_id de l'utilisateur connecté
    """
    files = db.list_user_files(current_user_id)

    if not files:
        print("\n  Aucun fichier dans votre espace.")
        return

    print(f"\n  {'Nom du fichier':<30} {'Ajouté le':<22} {'Modifié le'}")
    print("  " + "─" * 70)
    for f in files:
        created = f["created_at"][:16] if f["created_at"] else "?"
        updated = f["updated_at"][:16] if f["updated_at"] else "?"
        print(f"  {f['filename']:<30} {created:<22} {updated}")


def list_all_files_admin() -> None:
    """
    Affiche tous les fichiers de tous les utilisateurs.
    Réservé à l'admin. Affiche le propriétaire mais pas les métadonnées de chiffrement.
    """
    files = db.list_all_files()

    if not files:
        print("\n  Aucun fichier enregistré.")
        return

    print(f"\n  {'Propriétaire':<20} {'Nom du fichier':<30} {'Algo':<10} {'Ajouté le'}")
    print("  " + "─" * 75)
    for f in files:
        created = f["created_at"][:16] if f["created_at"] else "?"
        print(f"  {f['username']:<20} {f['filename']:<30} {f['crypto_mode']:<10} {created}")


import os
import hashlib
import base64
from database import (
    init_db, register_user, authenticate_user,
    change_username, change_password,
    get_all_users, get_user_audit_log, is_admin
)

# ─── UTILITAIRES TERMINAL ─────────────────────────────────────────────────────

def clear():
    os.system("cls" if os.name == "nt" else "clear")

def separator():
    print("─" * 50)

def header(title):
    clear()
    separator()
    print(f"  🔐 CRYPTOGRAPHIE — {title}")
    separator()
    print()

def pause():
    input("\n  [Appuie sur Entrée pour continuer]")

def input_prompt(label):
    return input(f"  {label} : ").strip()

def print_success(msg): print(f"\n  ✅ {msg}")
def print_error(msg):   print(f"\n  ❌ {msg}")
def print_info(msg):    print(f"\n  ℹ️  {msg}")


# ─── CHIFFREMENT / HACHAGE DE FICHIERS ───────────────────────────────────────

def xor_encrypt(data: bytes, key: str) -> bytes:
    """Chiffrement XOR simple avec une clé répétée."""
    key_bytes = key.encode("utf-8")
    return bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))


def hash_file(filepath: str, algorithm: str) -> str:
    """Calcule le hash d'un fichier (MD5, SHA-1, SHA-256, SHA-512)."""
    algos = {
        "1": ("MD5",    hashlib.md5),
        "2": ("SHA-1",  hashlib.sha1),
        "3": ("SHA-256",hashlib.sha256),
        "4": ("SHA-512",hashlib.sha512),
    }
    name, fn = algos[algorithm]
    h = fn()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return name, h.hexdigest()


# ─── MENU FICHIERS ────────────────────────────────────────────────────────────

def menu_chiffrer(user):
    header("Chiffrement de fichier")
    print("  Algorithme : XOR avec clé personnalisée")
    print("  (encodé en Base64 dans le fichier de sortie)\n")

    filepath = input_prompt("Chemin du fichier à chiffrer")
    if not os.path.isfile(filepath):
        print_error("Fichier introuvable.")
        pause(); return

    key = input_prompt("Clé de chiffrement")
    if not key:
        print_error("Clé vide.")
        pause(); return

    with open(filepath, "rb") as f:
        data = f.read()

    encrypted = xor_encrypt(data, key)
    encoded   = base64.b64encode(encrypted).decode("utf-8")

    out_path = filepath + ".enc"
    with open(out_path, "w") as f:
        f.write(encoded)

    print_success(f"Fichier chiffré → {out_path}")
    pause()


def menu_dechiffrer(user):
    header("Déchiffrement de fichier")

    filepath = input_prompt("Chemin du fichier .enc à déchiffrer")
    if not os.path.isfile(filepath):
        print_error("Fichier introuvable.")
        pause(); return

    key = input_prompt("Clé de déchiffrement")
    if not key:
        print_error("Clé vide.")
        pause(); return

    with open(filepath, "r") as f:
        encoded = f.read()

    try:
        encrypted = base64.b64decode(encoded)
        decrypted = xor_encrypt(encrypted, key)   # XOR est symétrique
    except Exception:
        print_error("Fichier invalide ou clé incorrecte.")
        pause(); return

    # Retire .enc pour le nom de sortie
    out_path = filepath.replace(".enc", ".dec") if filepath.endswith(".enc") else filepath + ".dec"
    with open(out_path, "wb") as f:
        f.write(decrypted)

    print_success(f"Fichier déchiffré → {out_path}")
    pause()


def menu_hasher(user):
    header("Hachage de fichier")
    print("  Choisir l'algorithme :\n")
    print("    1. MD5")
    print("    2. SHA-1")
    print("    3. SHA-256")
    print("    4. SHA-512")
    print()

    algo = input_prompt("Choix (1-4)")
    if algo not in ("1","2","3","4"):
        print_error("Choix invalide.")
        pause(); return

    filepath = input_prompt("Chemin du fichier")
    if not os.path.isfile(filepath):
        print_error("Fichier introuvable.")
        pause(); return

    name, digest = hash_file(filepath, algo)
    print()
    separator()
    print(f"  Algorithme : {name}")
    print(f"  Fichier    : {os.path.basename(filepath)}")
    print(f"  Hash       : {digest}")
    separator()
    pause()


def menu_fichiers(user):
    while True:
        header(f"Gestion des fichiers  —  {user['username']}")
        print("    1. Chiffrer un fichier")
        print("    2. Déchiffrer un fichier")
        print("    3. Hasher un fichier")
        print("    0. Retour")
        print()
        choix = input_prompt("Choix")

        if choix == "1": menu_chiffrer(user)
        elif choix == "2": menu_dechiffrer(user)
        elif choix == "3": menu_hasher(user)
        elif choix == "0": break
        else:
            print_error("Option invalide.")
            pause()


# ─── MENU PARAMÈTRES ─────────────────────────────────────────────────────────

def menu_parametres(user):
    while True:
        header(f"Paramètres  —  {user['username']}")
        print("    1. Changer de nom d'utilisateur")
        print("    2. Changer de mot de passe")
        print("    0. Retour")
        print()
        choix = input_prompt("Choix")

        if choix == "1":
            header("Changer de nom")
            new_name = input_prompt("Nouveau nom")
            res = change_username(user["user_id"], new_name)
            if res["success"]:
                user["username"] = new_name
                print_success("Nom modifié avec succès.")
            else:
                print_error(res["error"])
            pause()

        elif choix == "2":
            header("Changer de mot de passe")
            old_pwd = input_prompt("Ancien mot de passe")
            new_pwd = input_prompt("Nouveau mot de passe")
            res = change_password(user["user_id"], old_pwd, new_pwd)
            if res["success"]:
                print_success("Mot de passe modifié avec succès.")
            else:
                print_error(res["error"])
            pause()

        elif choix == "0":
            break
        else:
            print_error("Option invalide.")
            pause()


# ─── PANEL ADMIN ─────────────────────────────────────────────────────────────

def panel_admin(user):
    while True:
        header("Panel Admin")
        print("    1. Voir tous les utilisateurs")
        print("    2. Voir l'audit log d'un utilisateur")
        print("    0. Retour")
        print()
        choix = input_prompt("Choix")

        if choix == "1":
            header("Liste des utilisateurs")
            users = get_all_users(user["user_id"])
            if not users:
                print_info("Aucun utilisateur.")
            else:
                print(f"  {'ID':<5} {'Nom':<20} {'Actif':<8} {'Créé le'}")
                separator()
                for u in users:
                    actif = "Oui" if u["is_active"] else "Non"
                    created = u["created_at"][:10] if u["created_at"] else "?"
                    print(f"  {u['user_id']:<5} {u['username']:<20} {actif:<8} {created}")
            pause()

        elif choix == "2":
            header("Audit log d'un utilisateur")
            uid_str = input_prompt("ID de l'utilisateur")
            try:
                target_id = int(uid_str)
            except ValueError:
                print_error("ID invalide.")
                pause(); continue

            logs = get_user_audit_log(user["user_id"], target_id)
            if not logs:
                print_info("Aucune modification trouvée pour cet utilisateur.")
            else:
                print(f"\n  {'Date':<22} {'Action':<22} {'Avant':<20} {'Après'}")
                separator()
                for log in logs:
                    date   = log["timestamp"][:19] if log["timestamp"] else "?"
                    old    = (log["old_value"] or "")[:18]
                    new    = (log["new_value"] or "")[:18]
                    action = log["action"][:20]
                    print(f"  {date:<22} {action:<22} {old:<20} {new}")
            pause()

        elif choix == "0":
            break
        else:
            print_error("Option invalide.")
            pause()


# ─── MENU PRINCIPAL (après login) ────────────────────────────────────────────

def menu_principal(user):
    while True:
        header(f"Menu principal  —  {user['username']}")

        admin = is_admin(user["user_id"])
        print("    1. Gestion des fichiers")
        print("    2. Paramètres du compte")
        if admin:
            print("    3. Panel admin  👑")
        print("    0. Déconnexion")
        print()
        choix = input_prompt("Choix")

        if choix == "1":
            menu_fichiers(user)
        elif choix == "2":
            menu_parametres(user)
        elif choix == "3" and admin:
            panel_admin(user)
        elif choix == "0":
            print_info(f"Au revoir, {user['username']} !")
            pause()
            break
        else:
            print_error("Option invalide.")
            pause()


# ─── ÉCRAN D'ACCUEIL ─────────────────────────────────────────────────────────

def ecran_login():
    header("Connexion")
    username = input_prompt("Nom d'utilisateur")
    password = input_prompt("Mot de passe")
    res = authenticate_user(username, password)
    if res["success"]:
        print_success(f"Bienvenue, {res['user']['username']} !")
        pause()
        menu_principal(res["user"])
    else:
        print_error(res["error"])
        pause()


def ecran_register():
    header("Créer un compte")
    username = input_prompt("Nom d'utilisateur")
    password = input_prompt("Mot de passe")
    confirm  = input_prompt("Confirmer le mot de passe")

    if password != confirm:
        print_error("Les mots de passe ne correspondent pas.")
        pause(); return

    res = register_user(username, password)
    if res["success"]:
        print_success(f"Compte créé ! Tu peux maintenant te connecter.")
    else:
        print_error(res["error"])
    pause()


def main():
    init_db()

    while True:
        header("Accueil")
        print("    1. Se connecter")
        print("    2. Créer un compte")
        print("    0. Quitter")
        print()
        choix = input_prompt("Choix")

        if choix == "1":   ecran_login()
        elif choix == "2": ecran_register()
        elif choix == "0":
            clear()
            print("\n  À bientôt !\n")
            break
        else:
            print_error("Option invalide.")
            pause()


if __name__ == "__main__":
    main()

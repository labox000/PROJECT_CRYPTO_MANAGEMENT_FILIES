"""
main.py — Point d'entrée de l'application.

Lancement : python main.py

Flux :
    1. init_db()  — initialise la base et le compte admin au premier lancement
    2. Écran d'accueil  → connexion ou inscription
    3. Après login      → menu USER  ou  menu ADMIN selon le rôle
"""

import os
from pathlib import Path
import core.db as db
from core.db import init_db, delete_expired_sessions
from core.authentification import (
    register,
    login,
    logout,
    create_user_session,
    change_username,
    change_password,
    admin_delete_user,
    admin_reset_password,
)
from core.files import (
    add_file,
    open_file,
    modify_file,
    delete_file,
    verify_integrity,
    list_files,
    list_all_users_files,
    list_all_files_admin,
)
import core.objects as objects


# ═══════════════════════════════════════════════════════════════════════════════
#  UTILITAIRES TERMINAL
# ═══════════════════════════════════════════════════════════════════════════════

def clear() -> None:
    os.system("cls" if os.name == "nt" else "clear")

def separator(char: str = "─", width: int = 55) -> None:
    print("  " + char * width)

def header(title: str) -> None:
    clear()
    separator("═")
    print(f"  🔐  {title}")
    separator("═")
    print()

def pause() -> None:
    input("\n  [Appuyez sur Entrée pour continuer]")

def prompt(label: str) -> str:
    return input(f"  {label} : ").strip()

def prompt_password(label: str = "Mot de passe") -> str:
    """Saisie du mot de passe — masquée si possible, sinon visible."""
    try:
        import getpass
        return getpass.getpass(f"  {label} : ")
    except Exception:
        return input(f"  {label} : ").strip()

def ok(msg: str)   -> None: print(f"\n  ✅  {msg}")
def err(msg: str)  -> None: print(f"\n  ❌  {msg}")
def info(msg: str) -> None: print(f"\n  ℹ️   {msg}")
def warn(msg: str) -> None: print(f"\n  ⚠️   {msg}")


# ═══════════════════════════════════════════════════════════════════════════════
#  ÉCRAN D'ACCUEIL — INSCRIPTION / CONNEXION
# ═══════════════════════════════════════════════════════════════════════════════

def screen_register() -> None:
    """Écran d'inscription d'un nouvel utilisateur."""
    header("Créer un compte")
    username         = prompt("Nom d'utilisateur")
    password         = prompt_password("Mot de passe")
    confirm_password = prompt_password("Confirmer le mot de passe")

    success, msg = register(username, password, confirm_password)
    if success:
        ok(msg)
    else:
        err(msg)
    pause()


def screen_login() -> tuple[objects.User, objects.Session] | None:
    """
    Écran de connexion.
    Retourne (User, Session) si succès, None sinon.
    """
    header("Connexion")
    username = prompt("Nom d'utilisateur")
    password = prompt_password()

    success, result = login(username, password)
    if not success:
        err(result)
        pause()
        return None

    user    = result
    session = create_user_session(user.user_id)
    ok(f"Bienvenue, {user.username} !")
    pause()
    return user, session


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU UTILISATEUR — FICHIERS
# ═══════════════════════════════════════════════════════════════════════════════

def menu_files(user: objects.User) -> None:
    """Sous-menu de gestion des fichiers pour un utilisateur standard."""
    while True:
        header(f"Mes fichiers  —  {user.username}")
        print("    1. Voir mes fichiers")
        print("    2. Ajouter un fichier")
        print("    3. Ouvrir un fichier")
        print("    4. Modifier un fichier")
        print("    5. Supprimer un fichier")
        print("    6. Vérifier l'intégrité d'un fichier")
        print("    7. Voir les fichiers des autres utilisateurs")
        print("    0. Retour")
        print()
        choix = prompt("Choix")

        if choix == "1":
            header("Mes fichiers")
            list_files(user.user_id)
            pause()

        elif choix == "2":
            header("Ajouter un fichier")
            source = prompt("Chemin du fichier à ajouter")
            try:
                add_file(source, user.user_id)
            except FileExistsError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "3":
            header("Ouvrir un fichier")
            list_files(user.user_id)
            filename = prompt("\n  Nom du fichier à ouvrir")
            try:
                content = open_file(filename, user.user_id)
                separator()
                try:
                    print(content.decode("utf-8"))
                except UnicodeDecodeError:
                    warn("Ce fichier n'est pas du texte lisible (binaire).")
                separator()
            except PermissionError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except ValueError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "4":
            header("Modifier un fichier")
            list_files(user.user_id)
            filename   = prompt("\n  Nom du fichier à modifier")
            new_source = prompt("Chemin du fichier contenant le nouveau contenu")
            try:
                modify_file(filename, new_source, user.user_id)
            except PermissionError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "5":
            header("Supprimer un fichier")
            list_files(user.user_id)
            filename = prompt("\n  Nom du fichier à supprimer")
            warn(f"Confirmez-vous la suppression de '{filename}' ? (oui/non)")
            if prompt("Confirmation").lower() in ("oui", "o", "yes", "y"):
                try:
                    delete_file(filename, user.user_id)
                    ok(f"'{filename}' supprimé.")
                except PermissionError as e:
                    err(str(e))
                except FileNotFoundError as e:
                    err(str(e))
                except Exception as e:
                    err(f"Erreur inattendue : {e}")
            else:
                info("Suppression annulée.")
            pause()

        elif choix == "6":
            header("Vérifier l'intégrité")
            list_files(user.user_id)
            filename = prompt("\n  Nom du fichier à vérifier")
            try:
                verify_integrity(filename, user.user_id)
            except PermissionError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "7":
            header("Fichiers des autres utilisateurs")
            info("Vous pouvez voir les noms des fichiers mais pas leur contenu.")
            all_users = db.list_users()
            # Exclure l'utilisateur courant (il a déjà son propre menu)
            other_users = [u for u in all_users if u["user_id"] != user.user_id]
            if not other_users:
                info("Aucun autre utilisateur enregistré.")
            else:
                list_all_users_files(other_users)
            pause()

        elif choix == "0":
            break
        else:
            err("Option invalide.")
            pause()

        if choix == "1":
            header("Mes fichiers")
            list_files(user.user_id)
            pause()

        elif choix == "2":
            header("Ajouter un fichier")
            source = prompt("Chemin du fichier à ajouter")
            try:
                add_file(source, user.user_id)
            except FileExistsError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "3":
            header("Ouvrir un fichier")
            list_files(user.user_id)
            filename = prompt("\n  Nom du fichier à ouvrir")
            try:
                content = open_file(filename, user.user_id)
                separator()
                try:
                    print(content.decode("utf-8"))
                except UnicodeDecodeError:
                    warn("Ce fichier n'est pas du texte lisible (binaire).")
                    info("Utilisez 'Modifier' pour le remplacer par un fichier texte.")
                separator()
            except PermissionError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except ValueError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "4":
            header("Modifier un fichier")
            list_files(user.user_id)
            filename   = prompt("\n  Nom du fichier à modifier")
            new_source = prompt("Chemin du fichier contenant le nouveau contenu")
            try:
                modify_file(filename, new_source, user.user_id)
            except PermissionError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "5":
            header("Supprimer un fichier")
            list_files(user.user_id)
            filename = prompt("\n  Nom du fichier à supprimer")
            print(f"\n  ⚠️   Confirmez-vous la suppression de '{filename}' ? (oui/non)")
            if prompt("Confirmation").lower() in ("oui", "o", "yes", "y"):
                try:
                    delete_file(filename, user.user_id)
                    ok(f"'{filename}' supprimé.")
                except PermissionError as e:
                    err(str(e))
                except FileNotFoundError as e:
                    err(str(e))
                except Exception as e:
                    err(f"Erreur inattendue : {e}")
            else:
                info("Suppression annulée.")
            pause()

        elif choix == "6":
            header("Vérifier l'intégrité")
            list_files(user.user_id)
            filename = prompt("\n  Nom du fichier à vérifier")
            try:
                verify_integrity(filename, user.user_id)
            except PermissionError as e:
                err(str(e))
            except FileNotFoundError as e:
                err(str(e))
            except Exception as e:
                err(f"Erreur inattendue : {e}")
            pause()

        elif choix == "0":
            break
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU UTILISATEUR — PARAMÈTRES DU COMPTE
# ═══════════════════════════════════════════════════════════════════════════════

def menu_settings(user: objects.User) -> None:
    """Sous-menu de gestion du compte utilisateur."""
    while True:
        header(f"Paramètres  —  {user.username}")
        print("    1. Changer de nom d'utilisateur")
        print("    2. Changer de mot de passe")
        print("    0. Retour")
        print()
        choix = prompt("Choix")

        if choix == "1":
            header("Changer de nom d'utilisateur")
            new_username     = prompt("Nouveau nom d'utilisateur")
            current_password = prompt_password("Mot de passe actuel (confirmation)")
            success, msg = change_username(user.user_id, new_username, current_password)
            if success:
                user.username = new_username.strip().lower()
                ok(msg)
            else:
                err(msg)
            pause()

        elif choix == "2":
            header("Changer de mot de passe")
            old_password         = prompt_password("Ancien mot de passe")
            new_password         = prompt_password("Nouveau mot de passe")
            confirm_new_password = prompt_password("Confirmer le nouveau mot de passe")
            success, msg = change_password(
                user.user_id, old_password, new_password, confirm_new_password
            )
            if success:
                ok(msg)
            else:
                err(msg)
            pause()

        elif choix == "0":
            break
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU PRINCIPAL UTILISATEUR
# ═══════════════════════════════════════════════════════════════════════════════

def menu_user(user: objects.User, session: objects.Session) -> None:
    """Menu principal pour un utilisateur standard."""
    while True:
        # Vérification expiration session à chaque retour au menu
        if session.is_expired():
            warn("Votre session a expiré. Veuillez vous reconnecter.")
            logout(session.session_id, user.user_id)
            pause()
            return

        header(f"Menu principal  —  {user.username}")
        print("    1. Mes fichiers")
        print("    2. Paramètres du compte")
        print("    0. Déconnexion")
        print()
        choix = prompt("Choix")

        if choix == "1":
            menu_files(user)
        elif choix == "2":
            menu_settings(user)
        elif choix == "0":
            logout(session.session_id, user.user_id)
            ok(f"À bientôt, {user.username} !")
            pause()
            return
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU ADMIN — GESTION DES UTILISATEURS
# ═══════════════════════════════════════════════════════════════════════════════

def _display_users_table(users: list, show_sensitive: bool = False) -> None:
    """Affiche la liste des utilisateurs sous forme de tableau."""
    if not users:
        info("Aucun utilisateur enregistré.")
        return

    if show_sensitive:
        print(f"\n  {'Username':<20} {'Rôle':<8} {'Hash (SHA-256)':<66} {'Salt'}")
        separator()
        for u in users:
            print(f"  {u['username']:<20} {u['role']:<8} {u['password_hash']:<66} {u['salt']}")
    else:
        print(f"\n  {'ID':<38} {'Username':<20} {'Rôle':<8} {'Créé le'}")
        separator()
        for u in users:
            created = u["created_at"][:10] if u["created_at"] else "?"
            print(f"  {u['user_id']:<38} {u['username']:<20} {u['role']:<8} {created}")


def menu_admin_users(admin: objects.User) -> None:
    """Sous-menu admin : gestion complète des utilisateurs."""
    while True:
        header("Admin — Gestion des utilisateurs")
        print("    1. Voir tous les utilisateurs")
        print("    2. Voir les détails sensibles (hash + salt)")
        print("    3. Modifier le nom d'un utilisateur")
        print("    4. Réinitialiser le mot de passe d'un utilisateur")
        print("    5. Supprimer un utilisateur")
        print("    0. Retour")
        print()
        choix = prompt("Choix")

        if choix == "1":
            header("Liste des utilisateurs")
            users = db.list_users()
            _display_users_table(users, show_sensitive=False)
            pause()

        elif choix == "2":
            header("Détails sensibles — hash & salt")
            warn("Ces informations sont confidentielles.")
            users = db.list_users_admin()
            _display_users_table(users, show_sensitive=True)
            pause()

        elif choix == "3":
            header("Modifier le nom d'un utilisateur")
            users = db.list_users()
            _display_users_table(users, show_sensitive=False)
            target_id    = prompt("\n  user_id de l'utilisateur à modifier")
            new_username = prompt("Nouveau nom d'utilisateur")
            ok_db, msg   = db.update_username(target_id, new_username)
            if ok_db:
                db.create_log(
                    admin.user_id, "change_username",
                    f"Admin a changé le username de {target_id} → {new_username}"
                )
                ok(msg)
            else:
                err(msg)
            pause()

        elif choix == "4":
            header("Réinitialiser un mot de passe")
            users = db.list_users()
            _display_users_table(users, show_sensitive=False)
            target_id    = prompt("\n  user_id de l'utilisateur")
            new_password = prompt_password("Nouveau mot de passe")
            success, msg = admin_reset_password(admin, target_id, new_password)
            if success:
                ok(msg)
            else:
                err(msg)
            pause()

        elif choix == "5":
            header("Supprimer un utilisateur")
            users = db.list_users()
            _display_users_table(users, show_sensitive=False)
            target_id = prompt("\n  user_id de l'utilisateur à supprimer")

            target = db.get_user_by_id(target_id)
            if not target:
                err("Utilisateur introuvable.")
                pause()
                continue

            warn(f"Vous allez supprimer '{target['username']}' et TOUS ses fichiers.")
            print("  Cette action est irréversible. Confirmer ? (oui/non)")
            if prompt("Confirmation").lower() in ("oui", "o", "yes", "y"):
                success, msg = admin_delete_user(admin, target_id)
                if success:
                    ok(msg)
                else:
                    err(msg)
            else:
                info("Suppression annulée.")
            pause()

        elif choix == "0":
            break
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU ADMIN — LOGS
# ═══════════════════════════════════════════════════════════════════════════════

def _display_logs_table(logs: list) -> None:
    """Affiche les logs sous forme de tableau."""
    if not logs:
        info("Aucun log trouvé.")
        return

    print(f"\n  {'Date':<20} {'Username':<20} {'Action':<20} {'Détail'}")
    separator()
    for log in logs:
        date   = log["created_at"][:19] if log["created_at"] else "?"
        user   = log["username"][:18]
        action = log["action"][:18]
        detail = (log["detail"] or "")[:40]
        print(f"  {date:<20} {user:<20} {action:<20} {detail}")


def menu_admin_logs(admin: objects.User) -> None:
    """Sous-menu admin : consultation des logs."""
    while True:
        header("Admin — Logs")
        print("    1. Voir tous les logs")
        print("    2. Rechercher les logs d'un utilisateur")
        print("    0. Retour")
        print()
        choix = prompt("Choix")

        if choix == "1":
            header("Tous les logs")
            logs = db.get_all_logs()
            _display_logs_table(logs)
            pause()

        elif choix == "2":
            header("Logs par utilisateur")
            info("Vous pouvez rechercher par username, prénom/nom ou user_id.")
            query = prompt("Recherche")
            logs  = db.search_logs(query)
            _display_logs_table(logs)
            pause()

        elif choix == "0":
            break
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU ADMIN — FICHIERS
# ═══════════════════════════════════════════════════════════════════════════════

def menu_admin_files(admin: objects.User) -> None:
    """Sous-menu admin : vue globale des fichiers."""
    while True:
        header("Admin — Fichiers")
        print("    1. Voir tous les fichiers (tous les utilisateurs)")
        print("    0. Retour")
        print()
        choix = prompt("Choix")

        if choix == "1":
            header("Tous les fichiers")
            list_all_files_admin()
            pause()

        elif choix == "0":
            break
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  MENU PRINCIPAL ADMIN
# ═══════════════════════════════════════════════════════════════════════════════

def menu_admin(admin: objects.User, session: objects.Session) -> None:
    """Menu principal pour l'administrateur."""
    while True:
        # Vérification expiration session
        if session.is_expired():
            warn("Votre session a expiré. Veuillez vous reconnecter.")
            logout(session.session_id, admin.user_id)
            pause()
            return

        header(f"Panel Admin  —  {admin.username}  👑")
        print("    1. Gestion des utilisateurs")
        print("    2. Logs")
        print("    3. Fichiers")
        print("    4. Paramètres de mon compte")
        print("    0. Déconnexion")
        print()
        choix = prompt("Choix")

        if choix == "1":
            menu_admin_users(admin)
        elif choix == "2":
            menu_admin_logs(admin)
        elif choix == "3":
            menu_admin_files(admin)
        elif choix == "4":
            menu_settings(admin)
        elif choix == "0":
            logout(session.session_id, admin.user_id)
            ok(f"À bientôt, {admin.username} !")
            pause()
            return
        else:
            err("Option invalide.")
            pause()


# ═══════════════════════════════════════════════════════════════════════════════
#  POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    # Initialisation de la base + nettoyage des sessions expirées
    init_db()
    deleted = delete_expired_sessions()
    if deleted:
        info(f"{deleted} session(s) expirée(s) nettoyée(s).")

    while True:
        header("Bienvenue")
        print("    1. Se connecter")
        print("    2. Créer un compte")
        print("    0. Quitter")
        print()
        choix = prompt("Choix")

        if choix == "1":
            result = screen_login()
            if result is not None:
                user, session = result
                # Redirection automatique selon le rôle
                if user.role == "admin":
                    menu_admin(user, session)
                else:
                    menu_user(user, session)

        elif choix == "2":
            screen_register()

        elif choix == "0":
            clear()
            print("\n  À bientôt !\n")
            break

        else:
            err("Option invalide.")
            pause()


if __name__ == "__main__":
    main()
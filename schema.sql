

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
--  TABLE : Users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Users (
    user_id       TEXT        PRIMARY KEY,           -- UUID v4  ex: "a1b2c3d4-..."
    username      TEXT        NOT NULL UNIQUE,        -- nom normalisé (strip + lower)
    password_hash TEXT        NOT NULL,               -- hex SHA-256
    salt          TEXT        NOT NULL,               -- hex  os.urandom(32)
    role          TEXT        NOT NULL DEFAULT 'user' -- 'user' | 'admin'
                              CHECK (role IN ('user', 'admin')),
    created_at    TIMESTAMP   NOT NULL DEFAULT (datetime('now')),
    updated_at    TIMESTAMP   NOT NULL DEFAULT (datetime('now'))
);

CREATE TRIGGER IF NOT EXISTS trg_users_updated_at
    AFTER UPDATE ON Users
    FOR EACH ROW
BEGIN
    UPDATE Users SET updated_at = datetime('now') WHERE user_id = OLD.user_id;
END;

-- ------------------------------------------------------------
--  TABLE : Sessions
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Sessions (
    session_id  TEXT        PRIMARY KEY,             -- UUID v4
    user_id     TEXT        NOT NULL
                            REFERENCES Users(user_id) ON DELETE CASCADE,
    created_at  TIMESTAMP   NOT NULL DEFAULT (datetime('now')),
    expires_at  TIMESTAMP   NOT NULL                 -- created_at + durée configurée
);

-- Index pour accélérer la recherche par user_id
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON Sessions(user_id);

-- ------------------------------------------------------------
--  TABLE : Files
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Files (
    file_id         TEXT        PRIMARY KEY,                        -- UUID v4
    owner_id        TEXT        NOT NULL
                                REFERENCES Users(user_id) ON DELETE CASCADE,
    filename        TEXT        NOT NULL,                           -- nom original du fichier
    stored_path     TEXT        NOT NULL,                           -- chemin physique dans storage/
    crypto_mode     TEXT        NOT NULL,                           -- algo choisi : AES, DES, RSA...
    crypto_meta     TEXT        NOT NULL DEFAULT '{}',              -- JSON : clé chiffrée, IV, params
    integrity_hash  TEXT        NOT NULL,                           -- SHA-256 du contenu AVANT chiffrement
    created_at      TIMESTAMP   NOT NULL DEFAULT (datetime('now')),
    updated_at      TIMESTAMP   NOT NULL DEFAULT (datetime('now')),
 
    UNIQUE (owner_id, filename)                                     -- un user ne peut pas avoir deux fichiers du même nom
);
 
CREATE TRIGGER IF NOT EXISTS trg_files_updated_at
    AFTER UPDATE ON Files
    FOR EACH ROW
BEGIN
    UPDATE Files SET updated_at = datetime('now') WHERE file_id = OLD.file_id;
END;
 
CREATE INDEX IF NOT EXISTS idx_files_owner_id ON Files(owner_id);
 
-- ------------------------------------------------------------
--  TABLE : Logs
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Logs (
    log_id      TEXT        PRIMARY KEY,                            -- UUID v4
    user_id     TEXT        NOT NULL
                            REFERENCES Users(user_id) ON DELETE CASCADE,
    action      TEXT        NOT NULL,                               -- voir liste ci-dessous
    detail      TEXT        NOT NULL DEFAULT '',                    -- info complémentaire (ex: nom fichier)
    created_at  TIMESTAMP   NOT NULL DEFAULT (datetime('now'))
);
 
-- Actions possibles pour le champ 'action' :
--   'register'           inscription d'un nouveau compte
--   'login'              connexion réussie
--   'logout'             déconnexion
--   'login_failed'       tentative de connexion échouée
--   'change_username'    modification du nom d'utilisateur
--   'change_password'    modification du mot de passe
--   'add_file'           ajout d'un fichier (detail = nom du fichier)
--   'delete_file'        suppression d'un fichier (detail = nom du fichier)
--   'modify_file'        modification d'un fichier (detail = nom du fichier)
--   'verify_integrity'   vérification d'intégrité (detail = nom fichier + résultat)
 
CREATE INDEX IF NOT EXISTS idx_logs_user_id   ON Logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON Logs(created_at);
 
-- ------------------------------------------------------------
--  Compte admin par défaut
--  Généré dynamiquement au premier lancement par init_db() dans db.py
--  Ne pas modifier ce bloc — le vrai hash est inséré par le code
-- ------------------------------------------------------------
INSERT OR IGNORE INTO Users (user_id, username, password_hash, salt, role)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'PLACEHOLDER',
    'PLACEHOLDER',
    'admin'
);
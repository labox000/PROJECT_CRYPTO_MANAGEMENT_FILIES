

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
--  Compte admin par défaut (première connexion)
--  MDP : Admin123!  — À changer immédiatement après le premier login
--  hash SHA-256 de "Admin123!" + salt "00...0" (32 octets de zéros)
--  REMPLACER ces valeurs par un vrai hash généré avec hash_password()
-- ------------------------------------------------------------
INSERT OR IGNORE INTO Users (user_id, username, password_hash, salt, role)
VALUES (
    '00000000-0000-0000-0000-000000000001',
    'admin',
    'REMPLACER_PAR_HASH_REEL',
    'REMPLACER_PAR_SALT_REEL',
    'admin'
);

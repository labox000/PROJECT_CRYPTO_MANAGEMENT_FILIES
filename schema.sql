PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ------------------------------------------------------------
--  TABLE : Users
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Users (
    user_id       TEXT        PRIMARY KEY,
    username      TEXT        NOT NULL UNIQUE,
    password_hash TEXT        NOT NULL,
    salt          TEXT        NOT NULL,
    role          TEXT        NOT NULL DEFAULT 'user'
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
    session_id  TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL
                            REFERENCES Users(user_id) ON DELETE CASCADE,
    created_at  TIMESTAMP   NOT NULL DEFAULT (datetime('now')),
    expires_at  TIMESTAMP   NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON Sessions(user_id);

-- ------------------------------------------------------------
--  TABLE : Files
-- ------------------------------------------------------------
CREATE TABLE IF NOT EXISTS Files (
    file_id         TEXT        PRIMARY KEY,
    owner_id        TEXT        NOT NULL
                                REFERENCES Users(user_id) ON DELETE CASCADE,
    filename        TEXT        NOT NULL,
    stored_path     TEXT        NOT NULL,
    crypto_mode     TEXT        NOT NULL,
    crypto_meta     TEXT        NOT NULL DEFAULT '{}',
    integrity_hash  TEXT        NOT NULL,
    created_at      TIMESTAMP   NOT NULL DEFAULT (datetime('now')),
    updated_at      TIMESTAMP   NOT NULL DEFAULT (datetime('now')),

    UNIQUE (owner_id, filename)
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
    log_id      TEXT        PRIMARY KEY,
    user_id     TEXT        NOT NULL
                            REFERENCES Users(user_id) ON DELETE CASCADE,
    action      TEXT        NOT NULL,
    detail      TEXT        NOT NULL DEFAULT '',
    created_at  TIMESTAMP   NOT NULL DEFAULT (datetime('now'))
);

-- Actions possibles :
--   register, login, logout, login_failed,
--   change_username, change_password,
--   add_file, delete_file, modify_file, verify_integrity

CREATE INDEX IF NOT EXISTS idx_logs_user_id    ON Logs(user_id);
CREATE INDEX IF NOT EXISTS idx_logs_created_at ON Logs(created_at);

-- NOTE : plus de compte admin hardcodé.
-- Le premier utilisateur qui s'inscrit via register() devient automatiquement admin.
-- Voir authentification.py → register()
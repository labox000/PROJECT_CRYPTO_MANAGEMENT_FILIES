from datetime import datetime

class Session:

    def __init__(
        self,
        session_id: str,
        user_id: str,
        created_at: datetime | None = None,
        expires_at: datetime | None = None
    ):
        self.session_id = session_id
        self.user_id = user_id

        # if not provided, default to now
        self.created_at = created_at or datetime.now()

        # expires_at should be explicitly set by your logic
        self.expires_at = expires_at

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now() > self.expires_at
    

class User:

    def __init__(
        self,
        user_id: str,
        username: str,
        password_hash: str,
        salt:str ,
        role: str = "user",
        created_at: datetime | None = None,
        updated_at: datetime | None = None
    ):
        self.user_id = user_id
        self.username = username.strip().lower()
        self.password_hash = password_hash
        self.salt = salt
        self.role = role

        # default to now if not provided (matches DB DEFAULT CURRENT_TIMESTAMP concept)
        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()
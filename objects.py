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


from datetime import datetime


class File:

    def __init__(
        self,
        file_name: str,
        user_id: str,
        file_hash: str,
        encryption_state: str,
        encryption_algorithm=None,
        encrypted_key=None,
        created_at=None,
        updated_at=None
    ):

        self.user_id = user_id

        self.file_name = file_name
        self.file_hash = file_hash

        self.encryption_state = encryption_state
        self.encryption_algorithm = encryption_algorithm

        self.encrypted_key = encrypted_key

        self.created_at = created_at or datetime.now()
        self.updated_at = updated_at or datetime.now()

    def update_hash(self, new_hash):
        self.file_hash = new_hash
        self.updated_at = datetime.now()

    def set_encryption(
        self,
        state: str,
        algorithm=None,
        encrypted_key=None
    ):

        self.encryption_state = state
        self.encryption_algorithm = algorithm
        self.encrypted_key = encrypted_key

        self.updated_at = datetime.now()

    def rename_file(self, new_name):
        self.file_name = new_name
        self.updated_at = datetime.now()

    def display_info(self):

        
        print(f"File Name: {self.file_name}")
        print(f"User ID: {self.user_id}")


        print(f"Hash: {self.file_hash}")

        print(f"Encryption State: {self.encryption_state}")
        print(f"Encryption Algorithm: {self.encryption_algorithm}")

        print(f"Created At: {self.created_at}")
        print(f"Updated At: {self.updated_at}")
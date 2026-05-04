class User:
 
    def __init__(self, username: str, password_hash: str, salt: str):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
 
    def to_dict(self) -> dict:
        return {
            "username": self.username,
            "password_hash": self.password_hash,
            "salt": self.salt,
        }
 
    #methode stat
    def from_dict(data: dict) -> "User":
        return User(
            username=data["username"],
            password_hash=data["password_hash"],
            salt=data["salt"],
        )
 
    def __repr__(self):
        return f"User(username={self.username!r})" #affichage user
    
    
import bcrypt
from logging_config import logger

class Hasher:
    def hash_password(self, password):
        try:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
            return hashed.decode('utf-8')
        except Exception as e:
            logger.error("Error hashing password: %s", str(e))
            raise

    def verify_password(self, password, hashed):
        try:
            return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
        except Exception as e:
            logger.error("Error verifying password: %s", str(e))
            raise

if __name__ == "__main__":
    hasher = Hasher()
    
    # Hash a password
    password = "my_secure_password"
    hashed_password = hasher.hash_password(password)
    print("Hashed Password:", hashed_password)

    # Verify the password
    is_verified = hasher.verify_password("my_secure_password", hashed_password)
    print("Password Verified:", is_verified)

    # Attempt to verify with an incorrect password
    is_verified = hasher.verify_password("wrong_password", hashed_password)
    print("Password Verified with Wrong Password:", is_verified)

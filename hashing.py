from passlib.context import CryptContext

# Define your hashing algorithm and any additional options
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Hash():
    @staticmethod
    def bcrypt(password: str):
        return pwd_context.hash(password)

    @staticmethod
    def verify(hashed_password, plain_password):
        return pwd_context.verify(plain_password, hashed_password)

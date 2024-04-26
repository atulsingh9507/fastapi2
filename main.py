from fastapi import FastAPI, Depends, HTTPException, Cookie, Response, Header
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import jwt
import model
import schema
from database import engine, SessionLocal
from hashing import Hash
from pydantic import EmailStr

model.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Secret key for encoding and decoding JWT tokens
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30  # Token expiration time

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Modify the create_access_token function to include user ID
def create_access_token(user_id: int):
    to_encode = {"sub": user_id}
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


# User creation endpoint
@app.post("/users/", response_model=schema.User)
def create_user(user: schema.UserCreate, db: Session = Depends(get_db)):
    hashed_password = Hash.bcrypt(user.password)
     
    db_user = model.User(username=user.username, password=hashed_password, email=user.email)  # Passing email from request
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


# Login endpoint with JWT token generation
@app.post("/login/")
def login(username: str, password: str, response: Response, db: Session = Depends(get_db)):
    user = db.query(model.User).filter(model.User.username == username).first()
    if not user or not Hash.verify(user.password, password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    # Generate JWT token with user ID
    access_token = create_access_token(user.id)
    
    # Set token as a cookie
    response.set_cookie(key="access_token", value=access_token)
    
    return {"access_token": access_token, "token_type": "bearer"}

# Logout endpoint
@app.post("/logout/")
def logout(response: Response, access_token: str = Cookie(None)):
    if access_token is None:
        raise HTTPException(status_code=401, detail="Not logged in")

    try:
        token_data = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = token_data.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")

        # Clear the access token cookie
        response.delete_cookie(key="access_token")

        return {"message": "Logged out successfully"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Change password endpoint with JWT token authentication
@app.put("/change-password/")
def change_password(new_password: str, response: Response, access_token: str = Header(None), db: Session = Depends(get_db)):
    if access_token is None:
        raise HTTPException(status_code=401, detail="Not logged in")
    
    try:
        token_data = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = token_data.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token")
        
        # Find user by username
        user = db.query(model.User).filter(model.User.username == username).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Hash the new password
        hashed_password = Hash.bcrypt(new_password)
        
        # Update user's password
        user.password = hashed_password
        db.commit()
        
        return {"message": "Password changed successfully"}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

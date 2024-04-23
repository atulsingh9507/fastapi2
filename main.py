from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import model
import schema
from database import engine, SessionLocal
from hashing import Hash   # Import the Hash class from hashing.py

model.Base.metadata.create_all(bind=engine)

app = FastAPI()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/users/", response_model=schema.User)
def create_user(user: schema.UserCreate, db: Session = Depends(get_db)):
    hashed_password = Hash.bcrypt(user.password)  # Hash the password before storing
    db_user = model.User(username=user.username, password=hashed_password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/login/")
def login(username: str, password: str, db: Session = Depends(get_db)):
    user = db.query(model.User).filter(model.User.username == username).first()
    if not user or not Hash.verify(user.password, password):
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"message": "Login successful"}

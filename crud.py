from sqlalchemy.orm import Session
import model
import schema

def get_user_by_username(db: Session, username: str):
    return db.query(model.User).filter(model.User.username == username).first()

def create_user(db: Session, user: schema.UserCreate):
    db_user = model.User(username=user.username, password=user.password)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

from pydantic import BaseModel
from pydantic import EmailStr

class UserBase(BaseModel):
    username: str

class UserCreate(BaseModel):
    username: str
    password: str
    email: EmailStr  # New field for email address


class User(UserBase):
    id: int
    

    class Config:
        orm_mode = True

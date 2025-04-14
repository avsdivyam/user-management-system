from pydantic import BaseModel, EmailStr, Field, validator
from typing import List, Optional
from datetime import datetime

class UserBase(BaseModel):
    username: str
    email: EmailStr
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = True

class UserCreate(UserBase):
    password: str
    roles: Optional[List[str]] = []
    
    @validator('password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class UserUpdate(BaseModel):
    username: Optional[str] = None
    email: Optional[EmailStr] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_verified: Optional[bool] = None
    password: Optional[str] = None
    roles: Optional[List[str]] = None
    
    @validator('password')
    def password_strength(cls, v):
        if v is not None and len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class UserSettingsUpdate(BaseModel):
    theme: Optional[str] = None
    notifications_enabled: Optional[bool] = None
    two_factor_enabled: Optional[bool] = None
    language: Optional[str] = None
    timezone: Optional[str] = None

class UserSettings(BaseModel):
    theme: str
    notifications_enabled: bool
    two_factor_enabled: bool
    language: str
    timezone: str
    
    class Config:
        orm_mode = True

class UserInDB(UserBase):
    id: int
    is_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime] = None
    roles: List[str] = []
    
    class Config:
        orm_mode = True

class UserResponse(UserInDB):
    user_settings: Optional[UserSettings] = None

class UserList(BaseModel):
    users: List[UserInDB]
    total: int
    page: int
    page_size: int
    total_pages: int

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user_id: int
    username: str
    roles: List[str]

class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    roles: Optional[List[str]] = None
    permissions: Optional[List[str]] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class PasswordResetRequest(BaseModel):
    email: EmailStr

class PasswordReset(BaseModel):
    token: str
    new_password: str
    
    @validator('new_password')
    def password_strength(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class VerifyUserRequest(BaseModel):
    token: str
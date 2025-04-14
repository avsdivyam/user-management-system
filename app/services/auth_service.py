from datetime import datetime, timedelta
from typing import Optional
import os
import yaml
import jwt
from sqlalchemy.orm import Session
from app.models.user import User, Role, Permission
from app.database import get_db
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel

# Load configuration
config_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 'config', 'config_file.yaml')

try:
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    security_config = config.get('security', {})
    app_config = config.get('application', {})
except Exception as e:
    print(f"Error loading configuration: {e}")
    # Default configuration
    security_config = {
        'jwt_secret': 'default-jwt-secret',
        'jwt_algorithm': 'HS256',
        'jwt_expiration': 3600,
    }
    app_config = {
        'secret_key': 'default-secret-key',
    }

# JWT settings
SECRET_KEY = security_config.get('jwt_secret', app_config.get('secret_key', 'default-secret-key'))
ALGORITHM = security_config.get('jwt_algorithm', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = security_config.get('jwt_expiration', 3600) / 60

# OAuth2 scheme for token authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=True)

# Optional OAuth2 scheme that doesn't auto-error
class OAuth2PasswordBearerOptional(OAuth2PasswordBearer):
    async def __call__(self, request: Request = None):
        try:
            return await super().__call__(request)
        except HTTPException:
            return None

oauth2_scheme_optional = OAuth2PasswordBearerOptional(tokenUrl="/api/token", auto_error=False)

# Token data model
class TokenData(BaseModel):
    username: Optional[str] = None
    user_id: Optional[int] = None
    roles: Optional[list] = None
    permissions: Optional[list] = None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """
    Create a JWT access token
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str):
    """
    Verify a JWT token
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        user_id: int = payload.get("user_id")
        if username is None or user_id is None:
            return None
        return TokenData(username=username, user_id=user_id, 
                         roles=payload.get("roles", []), 
                         permissions=payload.get("permissions", []))
    except jwt.PyJWTError:
        return None

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get the current user from the token
    """
    token_data = verify_token(token)
    if token_data is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(User).filter(User.id == token_data.user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user

async def get_current_user_optional(token: str = Depends(oauth2_scheme_optional), db: Session = Depends(get_db)):
    """
    Optionally get the current user from the token.
    Returns None if the token is invalid or missing.
    """
    if token is None:
        return None
        
    try:
        token_data = verify_token(token)
        if token_data is None:
            return None

        user = db.query(User).filter(User.id == token_data.user_id).first()
        if user is None or not user.is_active:
            return None

        return user
    except:
        # If there's any error, just return None
        return None

async def get_current_user_optional(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
):
    """
    Optionally get the current user from the token.
    Returns None if the token is invalid or missing.
    """
    token_data = verify_token(token)
    if token_data is None:
        return None

    user = db.query(User).filter(User.id == token_data.user_id).first()
    if user is None or not user.is_active:
        return None

    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    """
    Get the current active user
    """
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def authenticate_user(db: Session, username: str, password: str):
    """
    Authenticate a user with username and password
    """
    user = db.query(User).filter(User.username == username).first()
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user

def check_admin_access(current_user: User = Depends(get_current_user)):
    """
    Check if the current user has admin access
    """
    if not current_user.is_admin() and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not enough permissions",
        )
    return current_user

def check_super_admin_access(current_user: User = Depends(get_current_user)):
    """
    Check if the current user has super admin access
    """
    if not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Super admin access required",
        )
    return current_user

def check_permission(permission_name: str):
    """
    Check if the current user has a specific permission
    """
    def permission_checker(current_user: User = Depends(get_current_user)):
        if not current_user.has_permission(permission_name) and not current_user.is_super_admin():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission '{permission_name}' required",
            )
        return current_user
    return permission_checker

def get_user_permissions(user: User, db: Session):
    """
    Get all permissions for a user
    """
    permissions = []
    for role in user.roles:
        for permission in role.permissions:
            if permission.name not in permissions:
                permissions.append(permission.name)
    return permissions
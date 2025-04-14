from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List

from app.database import get_db
from app.schemas.user import Token, LoginRequest, PasswordResetRequest, PasswordReset, VerifyUserRequest
from app.services.auth_service import (
    authenticate_user, create_access_token, get_current_user, get_user_permissions
)
from app.services.user_service import (
    get_user_by_email, generate_password_reset_token, reset_password, 
    verify_user, update_last_login, log_user_activity
)
from app.services.service_flag_service import check_service_flag_access
from app.models.user import User

router = APIRouter()

@router.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
    request: Request = None
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login time
    update_last_login(db, user.id)
    
    # Log login activity
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    log_user_activity(db, user.id, "user_login", "auth", None, 
                     f"User {user.username} logged in", ip_address, user_agent)
    
    # Get user roles and permissions
    role_names = [role.name for role in user.roles]
    permissions = get_user_permissions(user, db)
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "roles": role_names,
            "permissions": permissions
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800,  # 30 minutes in seconds
        "user_id": user.id,
        "username": user.username,
        "roles": role_names
    }

@router.post("/login", response_model=Token)
async def login(
    login_data: LoginRequest,
    db: Session = Depends(get_db),
    request: Request = None
):
    user = authenticate_user(db, login_data.username, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login time
    update_last_login(db, user.id)
    
    # Log login activity
    ip_address = request.client.host if request else None
    user_agent = request.headers.get("User-Agent") if request else None
    log_user_activity(db, user.id, "user_login", "auth", None, 
                     f"User {user.username} logged in", ip_address, user_agent)
    
    # Get user roles and permissions
    role_names = [role.name for role in user.roles]
    permissions = get_user_permissions(user, db)
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "roles": role_names,
            "permissions": permissions
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": 1800,  # 30 minutes in seconds
        "user_id": user.id,
        "username": user.username,
        "roles": role_names
    }

@router.post("/password-reset-request")
async def request_password_reset(
    reset_request: PasswordResetRequest,
    db: Session = Depends(get_db),
    request: Request = None
):
    # Check if password reset feature is enabled
    if not check_service_flag_access(db, "password_reset", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password reset functionality is currently disabled"
        )
    
    user = get_user_by_email(db, reset_request.email)
    if not user:
        # Don't reveal that the email doesn't exist
        return {"message": "If the email exists, a password reset link has been sent"}
    
    # Generate reset token
    token = generate_password_reset_token(db, reset_request.email)
    
    # In a real application, send an email with the reset link
    # For now, just return the token (this would be removed in production)
    return {
        "message": "Password reset link has been sent to your email",
        "token": token  # Remove this in production
    }

@router.post("/password-reset")
async def reset_user_password(
    reset_data: PasswordReset,
    db: Session = Depends(get_db),
    request: Request = None
):
    # Check if password reset feature is enabled
    if not check_service_flag_access(db, "password_reset", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password reset functionality is currently disabled"
        )
    
    user = reset_password(db, reset_data.token, reset_data.new_password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token"
        )
    
    return {"message": "Password has been reset successfully"}

@router.post("/verify")
async def verify_user_account(
    verify_data: VerifyUserRequest,
    db: Session = Depends(get_db)
):
    user = verify_user(db, verify_data.token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token"
        )
    
    return {"message": "User account has been verified successfully"}

@router.get("/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "id": current_user.id,
        "username": current_user.username,
        "email": current_user.email,
        "first_name": current_user.first_name,
        "last_name": current_user.last_name,
        "is_active": current_user.is_active,
        "is_verified": current_user.is_verified,
        "roles": [role.name for role in current_user.roles],
        "is_admin": current_user.is_admin(),
        "is_super_admin": current_user.is_super_admin()
    }

@router.get("/permissions")
async def read_user_permissions(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    permissions = get_user_permissions(current_user, db)
    return {"permissions": permissions}
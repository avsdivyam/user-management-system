from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from typing import List, Optional
import os

from app.database import get_db
from app.services.auth_service import (
    get_current_user, check_admin_access, check_super_admin_access
)
from app.services.user_service import (
    get_users, get_user_by_id, create_user, update_user, delete_user
)
from app.services.role_service import (
    get_roles, get_role_by_id, create_role, update_role, delete_role,
    get_permissions, get_permission_by_id, create_permission, update_permission, delete_permission
)
from app.services.service_flag_service import (
    get_service_flags, get_service_flag_by_id, update_service_flag
)
from app.services.audit_service import get_activity_summary
from app.models.user import User

router = APIRouter()

# Create templates
templates = Jinja2Templates(directory="templates")

@router.get("/dashboard", response_class=HTMLResponse)
async def admin_dashboard(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Get summary data for dashboard
    user_count = db.query(User).count()
    active_user_count = db.query(User).filter(User.is_active == True).count()
    
    # Get activity summary for last 7 days
    activity_summary = get_activity_summary(db, 7)
    
    # Get service flags
    is_super_admin = current_user.is_super_admin()
    flags = get_service_flags(db, 0, 100, None, True, True, is_super_admin)
    
    return templates.TemplateResponse(
        "admin/dashboard.html",
        {
            "request": request,
            "user": current_user,
            "user_count": user_count,
            "active_user_count": active_user_count,
            "activity_summary": activity_summary,
            "service_flags": flags,
            "is_super_admin": is_super_admin
        }
    )

@router.get("/users", response_class=HTMLResponse)
async def admin_users(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Calculate skip
    skip = (page - 1) * limit
    
    # Get users
    users = get_users(db, skip, limit, search)
    
    # Get total count
    total = db.query(User).count()
    
    # Get roles for user creation/editing
    roles = get_roles(db, 0, 100)
    
    return templates.TemplateResponse(
        "admin/users.html",
        {
            "request": request,
            "user": current_user,
            "users": users,
            "total": total,
            "page": page,
            "limit": limit,
            "search": search,
            "total_pages": (total + limit - 1) // limit,
            "roles": roles,
            "is_super_admin": current_user.is_super_admin()
        }
    )

@router.get("/roles", response_class=HTMLResponse)
async def admin_roles(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Calculate skip
    skip = (page - 1) * limit
    
    # Get roles
    roles = get_roles(db, skip, limit, search)
    
    # Get total count
    total = db.query(User).count()
    
    # Get permissions for role creation/editing
    permissions = get_permissions(db, 0, 100)
    
    return templates.TemplateResponse(
        "admin/roles.html",
        {
            "request": request,
            "user": current_user,
            "roles": roles,
            "total": total,
            "page": page,
            "limit": limit,
            "search": search,
            "total_pages": (total + limit - 1) // limit,
            "permissions": permissions,
            "is_super_admin": current_user.is_super_admin()
        }
    )

@router.get("/permissions", response_class=HTMLResponse)
async def admin_permissions(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_super_admin_access)
):
    # Calculate skip
    skip = (page - 1) * limit
    
    # Get permissions
    permissions = get_permissions(db, skip, limit, search)
    
    # Get total count
    total = db.query(User).count()
    
    return templates.TemplateResponse(
        "admin/permissions.html",
        {
            "request": request,
            "user": current_user,
            "permissions": permissions,
            "total": total,
            "page": page,
            "limit": limit,
            "search": search,
            "total_pages": (total + limit - 1) // limit
        }
    )

@router.get("/service-flags", response_class=HTMLResponse)
async def admin_service_flags(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Get service flags
    is_super_admin = current_user.is_super_admin()
    flags = get_service_flags(db, 0, 100, None, True, True, is_super_admin)
    
    return templates.TemplateResponse(
        "admin/service_flags.html",
        {
            "request": request,
            "user": current_user,
            "flags": flags,
            "is_super_admin": is_super_admin
        }
    )

@router.post("/service-flags/{flag_id}/toggle")
async def toggle_service_flag_admin(
    flag_id: int,
    db: Session = Depends(get_db),
    request: Request = None,
    current_user: User = Depends(check_admin_access)
):
    # Check if flag exists
    flag = get_service_flag_by_id(db, flag_id)
    if not flag:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Service flag not found"
        )
    
    # Check if user has access to toggle this flag
    is_super_admin = current_user.is_super_admin()
    
    if (flag.is_super_admin_only and not is_super_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have access to toggle this service flag"
        )
    
    # Toggle flag
    flag_dict = {
        "is_enabled": not flag.is_enabled,
        "ip_address": request.client.host if request else None,
        "user_agent": request.headers.get("User-Agent") if request else None
    }
    
    updated_flag = update_service_flag(db, flag_id, flag_dict, current_user.id)
    
    return {
        "id": updated_flag.id,
        "name": updated_flag.name,
        "is_enabled": updated_flag.is_enabled
    }

@router.get("/audit-logs", response_class=HTMLResponse)
async def admin_audit_logs(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # This is just a placeholder for the audit logs page
    # The actual logs will be loaded via API calls from the frontend
    
    return templates.TemplateResponse(
        "admin/audit_logs.html",
        {
            "request": request,
            "user": current_user,
            "page": page,
            "limit": limit,
            "is_super_admin": current_user.is_super_admin()
        }
    )

@router.get("/system-settings", response_class=HTMLResponse)
async def admin_system_settings(
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_super_admin_access)
):
    # This is for system-wide settings that only super admins can change
    
    return templates.TemplateResponse(
        "admin/system_settings.html",
        {
            "request": request,
            "user": current_user
        }
    )
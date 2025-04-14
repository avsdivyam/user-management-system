from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime, timedelta
import math

from app.database import get_db
from app.services.auth_service import (
    get_current_user, check_admin_access, check_super_admin_access, check_permission
)
from app.services.audit_service import (
    get_audit_log_by_id, get_audit_logs, get_user_activity, 
    get_resource_activity, get_activity_summary
)
from app.services.service_flag_service import check_service_flag_access
from app.models.user import User, AuditLog

router = APIRouter()

@router.get("/logs")
async def read_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    resource: Optional[str] = None,
    resource_id: Optional[int] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("audit:read"))
):
    # Check if audit logging is enabled
    if not check_service_flag_access(db, "audit_logging", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit logging is currently disabled"
        )
    
    # Regular users can only view their own audit logs
    if not current_user.is_admin() and not current_user.is_super_admin():
        user_id = current_user.id
    
    logs = get_audit_logs(
        db, skip, limit, user_id, action, resource, 
        resource_id, start_date, end_date, search
    )
    
    # Count total logs matching the filters
    query = db.query(AuditLog)
    
    if user_id:
        query = query.filter(AuditLog.user_id == user_id)
    
    if action:
        query = query.filter(AuditLog.action == action)
    
    if resource:
        query = query.filter(AuditLog.resource == resource)
    
    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)
    
    if start_date:
        query = query.filter(AuditLog.timestamp >= start_date)
    
    if end_date:
        query = query.filter(AuditLog.timestamp <= end_date)
    
    total = query.count()
    
    return {
        "logs": logs,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/logs/{log_id}")
async def read_audit_log(
    log_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("audit:read"))
):
    # Check if audit logging is enabled
    if not check_service_flag_access(db, "audit_logging", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit logging is currently disabled"
        )
    
    log = get_audit_log_by_id(db, log_id)
    if not log:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit log not found"
        )
    
    # Regular users can only view their own audit logs
    if not current_user.is_admin() and not current_user.is_super_admin() and log.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view this audit log"
        )
    
    return log

@router.get("/user/{user_id}")
async def read_user_audit_logs(
    user_id: int,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    days: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("audit:read"))
):
    # Check if audit logging is enabled
    if not check_service_flag_access(db, "audit_logging", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit logging is currently disabled"
        )
    
    # Regular users can only view their own audit logs
    if not current_user.is_admin() and not current_user.is_super_admin() and user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view this user's audit logs"
        )
    
    logs = get_user_activity(db, user_id, skip, limit, days)
    
    # Count total logs for this user
    query = db.query(AuditLog).filter(AuditLog.user_id == user_id)
    
    if days:
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(AuditLog.timestamp >= start_date)
    
    total = query.count()
    
    return {
        "logs": logs,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/resource/{resource}")
async def read_resource_audit_logs(
    resource: str,
    resource_id: Optional[int] = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    days: Optional[int] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(check_permission("audit:read"))
):
    # Check if audit logging is enabled
    if not check_service_flag_access(db, "audit_logging", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit logging is currently disabled"
        )
    
    # Only admins and super admins can view resource audit logs
    if not current_user.is_admin() and not current_user.is_super_admin():
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You don't have permission to view resource audit logs"
        )
    
    logs = get_resource_activity(db, resource, resource_id, skip, limit, days)
    
    # Count total logs for this resource
    query = db.query(AuditLog).filter(AuditLog.resource == resource)
    
    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)
    
    if days:
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(AuditLog.timestamp >= start_date)
    
    total = query.count()
    
    return {
        "logs": logs,
        "total": total,
        "page": math.floor(skip / limit) + 1,
        "page_size": limit,
        "total_pages": math.ceil(total / limit)
    }

@router.get("/summary")
async def read_activity_summary(
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    current_user: User = Depends(check_admin_access)
):
    # Check if audit logging is enabled
    if not check_service_flag_access(db, "audit_logging", False, False, False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Audit logging is currently disabled"
        )
    
    summary = get_activity_summary(db, days)
    
    return summary
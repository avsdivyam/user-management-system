from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, desc
from typing import List, Optional, Dict, Any
from app.models.user import AuditLog, User
from datetime import datetime, timedelta

def get_audit_log_by_id(db: Session, log_id: int) -> Optional[AuditLog]:
    """
    Get an audit log entry by ID
    """
    return db.query(AuditLog).filter(AuditLog.id == log_id).first()

def get_audit_logs(db: Session, skip: int = 0, limit: int = 100, 
                  user_id: int = None, action: str = None, resource: str = None, 
                  resource_id: int = None, start_date: datetime = None, 
                  end_date: datetime = None, search: str = None) -> List[AuditLog]:
    """
    Get audit logs with optional filters
    """
    query = db.query(AuditLog)
    
    # Apply filters
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
    
    if search:
        query = query.filter(
            or_(
                AuditLog.action.ilike(f"%{search}%"),
                AuditLog.resource.ilike(f"%{search}%"),
                AuditLog.details.ilike(f"%{search}%"),
                AuditLog.ip_address.ilike(f"%{search}%"),
                AuditLog.user_agent.ilike(f"%{search}%")
            )
        )
    
    # Order by timestamp descending (newest first)
    query = query.order_by(desc(AuditLog.timestamp))
    
    return query.offset(skip).limit(limit).all()

def get_user_activity(db: Session, user_id: int, skip: int = 0, limit: int = 100, 
                     days: int = None) -> List[AuditLog]:
    """
    Get activity for a specific user
    """
    query = db.query(AuditLog).filter(AuditLog.user_id == user_id)
    
    if days:
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(AuditLog.timestamp >= start_date)
    
    query = query.order_by(desc(AuditLog.timestamp))
    
    return query.offset(skip).limit(limit).all()

def get_resource_activity(db: Session, resource: str, resource_id: int = None, 
                         skip: int = 0, limit: int = 100, days: int = None) -> List[AuditLog]:
    """
    Get activity for a specific resource
    """
    query = db.query(AuditLog).filter(AuditLog.resource == resource)
    
    if resource_id:
        query = query.filter(AuditLog.resource_id == resource_id)
    
    if days:
        start_date = datetime.utcnow() - timedelta(days=days)
        query = query.filter(AuditLog.timestamp >= start_date)
    
    query = query.order_by(desc(AuditLog.timestamp))
    
    return query.offset(skip).limit(limit).all()

def get_activity_summary(db: Session, days: int = 30) -> Dict[str, Any]:
    """
    Get a summary of activity for the specified number of days
    """
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # Get total number of logs
    total_logs = db.query(AuditLog).filter(AuditLog.timestamp >= start_date).count()
    
    # Get logs by action
    action_counts = {}
    actions = db.query(AuditLog.action, db.func.count(AuditLog.id).label('count')) \
                .filter(AuditLog.timestamp >= start_date) \
                .group_by(AuditLog.action) \
                .all()
    
    for action, count in actions:
        action_counts[action] = count
    
    # Get logs by resource
    resource_counts = {}
    resources = db.query(AuditLog.resource, db.func.count(AuditLog.id).label('count')) \
                  .filter(AuditLog.timestamp >= start_date) \
                  .group_by(AuditLog.resource) \
                  .all()
    
    for resource, count in resources:
        resource_counts[resource] = count
    
    # Get most active users
    user_counts = {}
    users = db.query(AuditLog.user_id, db.func.count(AuditLog.id).label('count')) \
              .filter(AuditLog.timestamp >= start_date) \
              .group_by(AuditLog.user_id) \
              .order_by(desc('count')) \
              .limit(10) \
              .all()
    
    for user_id, count in users:
        user = db.query(User).filter(User.id == user_id).first()
        username = user.username if user else f"User {user_id}"
        user_counts[username] = count
    
    # Get activity by day
    daily_counts = {}
    days_query = db.query(
                    db.func.date_trunc('day', AuditLog.timestamp).label('day'),
                    db.func.count(AuditLog.id).label('count')
                ) \
                .filter(AuditLog.timestamp >= start_date) \
                .group_by('day') \
                .order_by('day') \
                .all()
    
    for day, count in days_query:
        daily_counts[day.strftime('%Y-%m-%d')] = count
    
    return {
        'total_logs': total_logs,
        'action_counts': action_counts,
        'resource_counts': resource_counts,
        'user_counts': user_counts,
        'daily_counts': daily_counts
    }

def create_audit_log(db: Session, log_data: Dict[str, Any]) -> AuditLog:
    """
    Create a new audit log entry
    """
    log = AuditLog(
        user_id=log_data.get("user_id"),
        action=log_data.get("action"),
        resource=log_data.get("resource"),
        resource_id=log_data.get("resource_id"),
        details=log_data.get("details"),
        ip_address=log_data.get("ip_address"),
        user_agent=log_data.get("user_agent"),
        timestamp=datetime.utcnow()
    )
    
    db.add(log)
    db.commit()
    db.refresh(log)
    
    return log
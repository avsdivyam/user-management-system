from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey, Table, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
import datetime
import uuid
from passlib.hash import bcrypt

Base = declarative_base()

# Association table for user-role many-to-many relationship
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, ForeignKey('users.id')),
    Column('role_id', Integer, ForeignKey('roles.id'))
)

# Association table for role-permission many-to-many relationship
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, ForeignKey('roles.id')),
    Column('permission_id', Integer, ForeignKey('permissions.id'))
)

class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    first_name = Column(String(50))
    last_name = Column(String(50))
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(100), unique=True)
    reset_token = Column(String(100), unique=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    last_login = Column(DateTime)
    
    # Relationships
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    user_settings = relationship("UserSettings", uselist=False, back_populates="user")
    audit_logs = relationship("AuditLog", back_populates="user")
    
    def set_password(self, password):
        self.password_hash = bcrypt.hash(password)
    
    def verify_password(self, password):
        return bcrypt.verify(password, self.password_hash)
    
    def generate_verification_token(self):
        self.verification_token = str(uuid.uuid4())
        return self.verification_token
    
    def generate_reset_token(self):
        self.reset_token = str(uuid.uuid4())
        return self.reset_token
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    def has_permission(self, permission_name):
        for role in self.roles:
            if any(perm.name == permission_name for perm in role.permissions):
                return True
        return False
    
    def is_admin(self):
        return self.has_role('admin')
    
    def is_super_admin(self):
        return self.has_role('super_admin')


class Role(Base):
    __tablename__ = 'roles'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(50), unique=True, nullable=False)
    description = Column(String(255))
    is_system_role = Column(Boolean, default=False)  # Indicates if this is a built-in role
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
    
    # Relationships
    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions, back_populates="roles")


class Permission(Base):
    __tablename__ = 'permissions'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    resource = Column(String(50))  # The resource this permission applies to
    action = Column(String(50))    # The action allowed on the resource (create, read, update, delete)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    roles = relationship("Role", secondary=role_permissions, back_populates="permissions")


class UserSettings(Base):
    __tablename__ = 'user_settings'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'), unique=True)
    theme = Column(String(20), default='light')
    notifications_enabled = Column(Boolean, default=True)
    two_factor_enabled = Column(Boolean, default=False)
    language = Column(String(10), default='en')
    timezone = Column(String(50), default='UTC')
    
    # Relationships
    user = relationship("User", back_populates="user_settings")


class AuditLog(Base):
    __tablename__ = 'audit_logs'
    
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    action = Column(String(50), nullable=False)
    resource = Column(String(50))
    resource_id = Column(Integer)
    details = Column(Text)
    ip_address = Column(String(50))
    user_agent = Column(String(255))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Relationships
    user = relationship("User", back_populates="audit_logs")


class ServiceFlag(Base):
    __tablename__ = 'service_flags'
    
    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(String(255))
    is_enabled = Column(Boolean, default=True)
    is_developer_only = Column(Boolean, default=False)  # Restricted to developer access
    is_admin_only = Column(Boolean, default=False)      # Restricted to admin access
    is_super_admin_only = Column(Boolean, default=False)  # Restricted to super admin access
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)
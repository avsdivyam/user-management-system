import uvicorn
from fastapi import FastAPI, Depends, HTTPException, status, Request, Response, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from sqlalchemy.orm import Session
import os
import yaml

from app.database import init_db, get_db
from app.controllers import (
    auth_controller, user_controller, role_controller, 
    service_flag_controller, audit_controller, admin_controller
)
from app.models.user import User, Role, Permission, ServiceFlag
from app.services.auth_service import get_current_user, get_current_user_optional, authenticate_user, create_access_token, verify_token
from app.services.user_service import update_last_login

# Load configuration
config_path = os.path.join(os.path.dirname(__file__), 'config', 'config_file.yaml')

try:
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    app_config = config.get('application', {})
    cors_config = app_config.get('cors_origins', ["http://localhost:8001", "http://127.0.0.1:8001"])
except Exception as e:
    print(f"Error loading configuration: {e}")
    # Default configuration
    app_config = {
        'name': 'User Management System',
        'debug': True
    }
    cors_config = ["http://localhost:8001", "http://127.0.0.1:8001"]

# Create FastAPI app
app = FastAPI(
    title=app_config.get('name', 'User Management System'),
    description="A comprehensive user management system with role-based access control",
    version=app_config.get('version', '1.0.0'),
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_config,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Include routers
app.include_router(auth_controller.router, prefix="/api", tags=["Authentication"])
app.include_router(user_controller.router, prefix="/api/users", tags=["Users"])
app.include_router(role_controller.router, prefix="/api/roles", tags=["Roles"])
app.include_router(service_flag_controller.router, prefix="/api/service-flags", tags=["Service Flags"])
app.include_router(audit_controller.router, prefix="/api/audit", tags=["Audit Logs"])
app.include_router(admin_controller.router, prefix="/api/admin", tags=["Admin"])

# Add token endpoint for OAuth2 authentication
@app.post("/api/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
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
            detail="Inactive user",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Update last login time
    update_last_login(db, user.id)
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "roles": [role.name for role in user.roles]
        },
        expires_delta=access_token_expires
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "roles": [role.name for role in user.roles]
    }

# Create templates
templates = Jinja2Templates(directory="templates")

# Helper function to get authenticated user from request
async def get_user_from_request(request: Request, db: Session):
    # Check for token in cookies
    token = request.cookies.get("access_token")
    if not token or not token.startswith("Bearer "):
        return None
    
    token = token.replace("Bearer ", "")
    try:
        # Verify token
        token_data = verify_token(token)
        if not token_data:
            return None
        
        # Get user from database
        user = db.query(User).filter(User.id == token_data.user_id).first()
        if not user or not user.is_active:
            return None
        
        return user
    except:
        return None

# Initialize database and create initial data
@app.on_event("startup")
async def startup_event():
    # Initialize database
    init_db()
    
    # Create initial data (superadmin, roles, permissions)
    db = next(get_db())
    create_initial_data(db)

def create_initial_data(db: Session):
    # Check if we already have a superadmin role
    superadmin_role = db.query(Role).filter(Role.name == "super_admin").first()
    if not superadmin_role:
        # Create roles
        superadmin_role = Role(
            name="super_admin",
            description="Super Administrator with full system access",
            is_system_role=True
        )
        admin_role = Role(
            name="admin",
            description="Administrator with management access",
            is_system_role=True
        )
        user_role = Role(
            name="user",
            description="Regular user with basic access",
            is_system_role=True
        )
        
        db.add_all([superadmin_role, admin_role, user_role])
        db.commit()
        
        # Create permissions
        permissions = [
            Permission(name="user:create", description="Create users", resource="users", action="create"),
            Permission(name="user:read", description="Read users", resource="users", action="read"),
            Permission(name="user:update", description="Update users", resource="users", action="update"),
            Permission(name="user:delete", description="Delete users", resource="users", action="delete"),
            Permission(name="role:create", description="Create roles", resource="roles", action="create"),
            Permission(name="role:read", description="Read roles", resource="roles", action="read"),
            Permission(name="role:update", description="Update roles", resource="roles", action="update"),
            Permission(name="role:delete", description="Delete roles", resource="roles", action="delete"),
            Permission(name="permission:create", description="Create permissions", resource="permissions", action="create"),
            Permission(name="permission:read", description="Read permissions", resource="permissions", action="read"),
            Permission(name="permission:update", description="Update permissions", resource="permissions", action="update"),
            Permission(name="permission:delete", description="Delete permissions", resource="permissions", action="delete"),
            Permission(name="service_flag:create", description="Create service flags", resource="service_flags", action="create"),
            Permission(name="service_flag:read", description="Read service flags", resource="service_flags", action="read"),
            Permission(name="service_flag:update", description="Update service flags", resource="service_flags", action="update"),
            Permission(name="service_flag:delete", description="Delete service flags", resource="service_flags", action="delete"),
            Permission(name="audit:read", description="Read audit logs", resource="audit_logs", action="read"),
        ]
        
        db.add_all(permissions)
        db.commit()
        
        # Assign permissions to roles
        superadmin_role = db.query(Role).filter(Role.name == "super_admin").first()
        admin_role = db.query(Role).filter(Role.name == "admin").first()
        user_role = db.query(Role).filter(Role.name == "user").first()
        
        # Super admin gets all permissions
        all_permissions = db.query(Permission).all()
        superadmin_role.permissions = all_permissions
        
        # Admin gets most permissions except some critical ones
        admin_permissions = db.query(Permission).filter(
            Permission.name.notin_(["role:delete", "permission:delete"])
        ).all()
        admin_role.permissions = admin_permissions
        
        # Regular users get basic read permissions
        user_permissions = db.query(Permission).filter(
            Permission.name.in_(["user:read", "role:read"])
        ).all()
        user_role.permissions = user_permissions
        
        db.commit()
        
        # Create default superadmin user
        superadmin = User(
            username="superadmin",
            email="superadmin@example.com",
            first_name="Super",
            last_name="Admin",
            is_active=True,
            is_verified=True
        )
        superadmin.set_password("superadmin123")  # This should be changed immediately
        superadmin.roles = [superadmin_role]
        
        db.add(superadmin)
        db.commit()
        
        # Create service flags
        service_flags = [
            ServiceFlag(
                name="user_registration",
                description="Allow new user registration",
                is_enabled=True
            ),
            ServiceFlag(
                name="password_reset",
                description="Allow password reset functionality",
                is_enabled=True
            ),
            ServiceFlag(
                name="audit_logging",
                description="Enable audit logging",
                is_enabled=True
            ),
            ServiceFlag(
                name="maintenance_mode",
                description="System maintenance mode",
                is_enabled=False,
                is_super_admin_only=True
            )
        ]
        
        db.add_all(service_flags)
        db.commit()

# UI Routes
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    # Check for token in cookies
    token = request.cookies.get("access_token")
    if token and token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
        try:
            # Verify token
            token_data = verify_token(token)
            if token_data:
                return RedirectResponse(url="/dashboard")
        except:
            pass
    
    # No valid token, show login page
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    # Check for token in cookies
    token = request.cookies.get("access_token")
    if token and token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
        try:
            # Verify token
            token_data = verify_token(token)
            if token_data:
                return RedirectResponse(url="/dashboard")
        except:
            pass
    
    # No valid token, show login page
    return templates.TemplateResponse("login.html", {"request": request, "error": None})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request, db: Session = Depends(get_db)):
    user = await get_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse("dashboard.html", {"request": request, "user": user})

@app.get("/profile", response_class=HTMLResponse)
async def profile(request: Request, db: Session = Depends(get_db)):
    user = await get_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse("profile.html", {"request": request, "user": user})

@app.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, db: Session = Depends(get_db)):
    user = await get_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    if not user.is_admin() and not user.is_super_admin():
        return RedirectResponse(url="/dashboard")
    
    return templates.TemplateResponse("users.html", {"request": request, "user": user})

@app.get("/roles", response_class=HTMLResponse)
async def roles_page(request: Request, db: Session = Depends(get_db)):
    user = await get_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    if not user.is_admin() and not user.is_super_admin():
        return RedirectResponse(url="/dashboard")
    
    return templates.TemplateResponse("roles.html", {"request": request, "user": user})

@app.get("/service-flags", response_class=HTMLResponse)
async def service_flags_page(request: Request, db: Session = Depends(get_db)):
    user = await get_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    if not user.is_admin() and not user.is_super_admin():
        return RedirectResponse(url="/dashboard")
    
    return templates.TemplateResponse("service_flags.html", {"request": request, "user": user})

@app.get("/audit-logs", response_class=HTMLResponse)
async def audit_logs_page(request: Request, db: Session = Depends(get_db)):
    user = await get_user_from_request(request, db)
    if not user:
        return RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    
    if not user.is_admin() and not user.is_super_admin():
        return RedirectResponse(url="/dashboard")
    
    return templates.TemplateResponse("audit_logs.html", {"request": request, "user": user})

@app.get("/forgot-password", response_class=HTMLResponse)
async def forgot_password_page(request: Request, db: Session = Depends(get_db)):
    # Check if user is already logged in
    user = await get_user_from_request(request, db)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse("forgot_password.html", {"request": request})

@app.get("/reset-password/{token}", response_class=HTMLResponse)
async def reset_password_page(request: Request, token: str, db: Session = Depends(get_db)):
    # Check if user is already logged in
    user = await get_user_from_request(request, db)
    if user:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    
    return templates.TemplateResponse("reset_password.html", {"request": request, "token": token})

@app.post("/login", response_class=HTMLResponse)
async def login_form(request: Request, username: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    user = authenticate_user(db, username, password)
    if not user:
        return templates.TemplateResponse("login.html", {"request": request, "error": "Invalid username or password"})
    
    if not user.is_active:
        return templates.TemplateResponse("login.html", {"request": request, "error": "User account is inactive"})
    
    # Update last login time
    update_last_login(db, user.id)
    
    # Create access token
    access_token_expires = timedelta(minutes=30)
    access_token = create_access_token(
        data={
            "sub": user.username,
            "user_id": user.id,
            "roles": [role.name for role in user.roles]
        },
        expires_delta=access_token_expires
    )
    
    # Set cookie and redirect
    response = RedirectResponse(url="/dashboard", status_code=status.HTTP_302_FOUND)
    response.set_cookie(key="access_token", value=f"Bearer {access_token}", httponly=True)
    
    return response

@app.get("/logout")
async def logout():
    response = RedirectResponse(url="/login", status_code=status.HTTP_302_FOUND)
    response.delete_cookie(key="access_token")
    return response

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8001, reload=True)
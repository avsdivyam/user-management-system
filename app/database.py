from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import os
import yaml

# Load configuration
config_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'config', 'config_file.yaml')

try:
    with open(config_path, 'r') as file:
        config = yaml.safe_load(file)
    db_config = config.get('database', {})
except Exception as e:
    print(f"Error loading configuration: {e}")
    # Default configuration
    db_config = {
        'host': 'localhost',
        'port': 5555,
        'name': 'user-management-system',
        'user': 'postgres',
        'password': '12345',
    }

# Construct database URL
DB_URL = f"postgresql://{db_config.get('user')}:{db_config.get('password')}@{db_config.get('host')}:{db_config.get('port')}/{db_config.get('name')}"

# Create SQLAlchemy engine
engine = create_engine(DB_URL)

# Create session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Function to initialize database
def init_db():
    from app.models.user import Base
    Base.metadata.create_all(bind=engine)
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Get DB connection details from environment
DB_URL = os.getenv("POSTGRES_URL")
if not DB_URL:
    # Fallback to manual construction for dev environments.
    POSTGRES_USER = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD", "postgres")
    POSTGRES_DB = os.getenv("POSTGRES_DB", "directorydb")
    POSTGRES_HOST = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT = os.getenv("POSTGRES_PORT", "5432")
    DB_URL = f"postgresql+psycopg2://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

engine = create_engine(DB_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# PUBLIC_INTERFACE
def get_db():
    """Yield SQLAlchemy DB session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

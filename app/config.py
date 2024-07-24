import os
from dotenv import load_dotenv

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

class Config:
    """Base configuración."""
    
    SECRET_KEY = os.getenv('SECRET_KEY')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY')
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # Access token expiration time in seconds
    CSRF_ENABLED = False
    WTF_CSRF_ENABLED = False  # Desactivar CSRF
    CSRF_SESSION_KEY = os.getenv('CSRF_SESSION_KEY')
    LIM_LIMIT = "200 per hour"  # Example rate limit

    # Configuración de la base de datos
    DATABASE_DRIVER = os.getenv('DATABASE_DRIVER')
    DATABASE_SERVER = os.getenv('DATABASE_SERVER')
    DATABASE_NAME = os.getenv('DATABASE_NAME')
    DATABASE_USER = os.getenv('DATABASE_USER')
    DATABASE_PASSWORD = os.getenv('DATABASE_PASSWORD')

    SQLALCHEMY_DATABASE_URI = (
        f'DRIVER={DATABASE_DRIVER};'
        f'SERVER={DATABASE_SERVER};'
        f'DATABASE={DATABASE_NAME};'
        f'UID={DATABASE_USER};'
        f'PWD={DATABASE_PASSWORD}'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Logging configuration
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'DEBUG')

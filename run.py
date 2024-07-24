from flask import Flask
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import os
from dotenv import load_dotenv

# Cargar variables de entorno desde .env
load_dotenv()

# Importar Config desde app/config.py
from app.config import Config
from app.routes import bp as routes_bp

# Crear instancia de Flask
app = Flask(__name__)

# Configurar la aplicación desde config.py
app.config.from_object(Config)

# Configurar el gestor de JWT
jwt = JWTManager(app)

# Configurar CSRF Protection
csrf = CSRFProtect(app)
if os.getenv('FLASK_ENV') == 'development':
    csrf._csrf_disable = True  # Deshabilitar CSRF en desarrollo

# Configurar el limitador de tasa
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=[app.config['LIM_LIMIT']],
)

# Registrar el blueprint
app.register_blueprint(routes_bp)

# Configurar logging
logging.basicConfig(level=app.config['LOG_LEVEL'])
logger = logging.getLogger(__name__)

@app.route('/')
def home():
    return "Welcome to the Flask App"

if __name__ == '__main__':
    app.run(debug=True)

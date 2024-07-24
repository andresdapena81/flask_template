from flask import Flask
from flask_jwt_extended import JWTManager
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os
import logging

def create_app():
    app = Flask(__name__)

    # Configuración de la aplicación
    app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'default-secret')
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['DEBUG'] = False

    # Inicialización de extensiones
    jwt = JWTManager(app)
    csrf = CSRFProtect(app)
    limiter = Limiter(
        get_remote_address,
        app=app,
        default_limits=["200 per day", "50 per hour"]
    )

    # Configuración de logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    with app.app_context():
        # Importar y registrar blueprints
        from . import routes
        app.register_blueprint(routes.bp)

    return app

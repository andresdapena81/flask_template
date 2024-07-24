from datetime import datetime
from flask import Blueprint, jsonify, request, current_app
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from marshmallow import Schema, fields, validate, ValidationError
from PIL import Image
import pytesseract
import logging
import pyodbc
import hashlib
from app.utils import extract_meds_from_text

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'

bp = Blueprint('routes', __name__)
logger = logging.getLogger(__name__)

users = {"user1": "password1"}
items = []

class ItemSchema(Schema):
    name = fields.String(required=True, validate=validate.Length(min=1))
    description = fields.String(required=True, validate=validate.Length(min=1))

item_schema = ItemSchema()

def get_db_connection():
    """Establish and return a database connection using configuration."""
    conn_str = (
        f'DRIVER={current_app.config["DATABASE_DRIVER"]};'
        f'SERVER={current_app.config["DATABASE_SERVER"]};'
        f'DATABASE={current_app.config["DATABASE_NAME"]};'
        f'UID={current_app.config["DATABASE_USER"]};'
        f'PWD={current_app.config["DATABASE_PASSWORD"]}'
    )
    return pyodbc.connect(conn_str)

@bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"msg": "Username and password required"}), 400

    # Conectar a la base de datos
    conn = get_db_connection()
    cursor = conn.cursor()

    # Consultar la base de datos para obtener el usuario y la contraseña
    cursor.execute("SELECT password FROM usuarios WHERE login = ?", username)
    row = cursor.fetchone()
    conn.close()

    if row:
        stored_password_hash = row[0]
        # Encriptar la contraseña proporcionada usando SHA-512
        password_hash = hashlib.sha512(password.encode()).hexdigest()

        # Comparar las contraseñas
        if stored_password_hash == password_hash:
            access_token = create_access_token(identity=username)
            return jsonify(access_token=access_token)

    return jsonify({"msg": "Invalid credentials"}), 401

@bp.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@bp.route('/items', methods=['GET'])
@jwt_required()
def get_items():
    current_user = get_jwt_identity()
    logger.info(f'User {current_user} accessed /items')
    return jsonify(items)

@bp.route('/items/<int:item_id>', methods=['GET'])
@jwt_required()
def get_item(item_id):
    current_user = get_jwt_identity()
    logger.info(f'User {current_user} accessed /items/{item_id}')
    item = next((item for item in items if item['id'] == item_id), None)
    return jsonify(item) if item else ('', 404)

@bp.route('/items', methods=['POST'])
@jwt_required()
def create_item():
    data = request.get_json()
    try:
        validated_data = item_schema.load(data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    new_item = {
        'id': len(items) + 1,
        'name': validated_data['name'],
        'description': validated_data['description']
    }
    items.append(new_item)
    current_user = get_jwt_identity()
    logger.info(f'User {current_user} created item {new_item}')
    return jsonify(new_item), 201

@bp.route('/items/<int:item_id>', methods=['PUT'])
@jwt_required()
def update_item(item_id):
    data = request.get_json()
    try:
        validated_data = item_schema.load(data)
    except ValidationError as err:
        return jsonify(err.messages), 400

    item = next((item for item in items if item['id'] == item_id), None)
    if item:
        item['name'] = validated_data['name']
        item['description'] = validated_data['description']
        current_user = get_jwt_identity()
        logger.info(f'User {current_user} updated item {item}')
        return jsonify(item)
    return ('', 404)

@bp.route('/items/<int:item_id>', methods=['DELETE'])
@jwt_required()
def delete_item(item_id):
    global items
    items = [item for item in items if item['id'] != item_id]
    current_user = get_jwt_identity()
    logger.info(f'User {current_user} deleted item {item_id}')
    return ('', 204)

@bp.route('/ocr', methods=['POST'])
@jwt_required()
def ocr_process():
    try:
        if request.method == 'POST':
            image_file = request.files['image']
            image_data = Image.open(image_file)

            # Perform OCR using PyTesseract
            text = pytesseract.image_to_string(image_data)

            # Conectar a la base de datos
            conn = get_db_connection()
            cursor = conn.cursor()
            resultados = extract_meds_from_text(text)

            # Insertar el texto OCR en la tabla formulas
            cursor.execute("INSERT INTO formulas (fecha, formula) VALUES (?, ?)", (datetime.now(), resultados))
            conn.commit()
            conn.close()

            response = {
                'status': 'success',
                'meds': resultados,
                'text': text
            }

        return jsonify(response)
    except ValidationError as err:
        return jsonify(err.messages), 400
    except pytesseract.pytesseract.TesseractNotFoundError:
        logging.error("Error processing OCR: tesseract is not installed or it's not in your PATH.")
        return jsonify({"error": "Tesseract is not installed or it's not in your PATH"}), 500
    except Exception as e:
        logging.error(f"Error processing OCR: {e}")
        return jsonify({"error": "An error occurred while processing the OCR"}), 500

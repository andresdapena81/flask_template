"""This module is for text processing."""
import os
import openai
from dotenv import load_dotenv

# Cargar las variables de entorno desde el archivo .env
load_dotenv()

# Acceder a la API Key
openai.api_key = os.getenv('OPENAI_API_KEY')

def extract_meds_from_text(texto):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo-16k",
        messages=[
            {
                "role": "user",
                "content": "El siguiente texto corresponde a una fórmula médica recuperada con un OCR. Necesito que lo leas y extraigas los medicamentos que contiene la fórmula y me devuelvas un texto con los medicamentos separados por comas: " + texto,
            }
        ]
    )

    respuesta = response.choices[0].message["content"]

    # Puedes procesar la respuesta aquí si es necesario
    medicamentos = respuesta

    return medicamentos


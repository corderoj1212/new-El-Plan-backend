import base64
import csv
import io
import logging
import os
import random
import re
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import bcrypt
import jwt
import magic
import pyqrcode
from Crypto.Cipher import AES
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from email_validator import EmailNotValidError, validate_email
from flask import (
    Flask,
    Response,
    abort,
    jsonify,
    make_response,
    request,
    send_from_directory,
)
from flask_cors import CORS
from mysql.connector import pooling
from werkzeug.utils import secure_filename

# Configurar el registro de errores
logging.basicConfig(level=logging.DEBUG)

# Paso 2: Cargar variables de entorno desde el archivo .env común
load_dotenv("/home/saries/El-Plan/.env")

# Crear instancia de Flask
app = Flask(__name__)
CORS(
    app,
    resources={
        r"/*": {
            "origins": [
                "https://elplanmadrid.org",
                "http://10.0.0.101:3000",
                "http://localhost:3000",
                "http://192.168.1.166:3000",
            ],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": [
                "Authorization",
                "Content-Type",
                "X-Requested-With",
                "Accept",
            ],
        }
    },
)


# Configuración JWT
SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
TOKEN_EXPIRY_DAYS = 7

# Configuración QR
QR_KEY = Fernet(os.getenv("QR_KEY"))

# Configuración de Base de Datos
DB_HOST = os.getenv("DB_HOST", "furberia.org")
DB_USER = os.getenv("DB_USER", "furberia")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_PORT = int(os.getenv("DB_PORT", 1206))
DB_NAME = os.getenv("DB_NAME", "furberia")

# Directorio imágenes
EVENT_DIR = os.getenv("EVENT_DIR", "/dev/null")
CIPHER_KEY = os.getenv("ENC_PASSWORD").encode()

# Configuracion correo
"""os.getenv("MAIL_PASS")"""
smtp_server = "smtp.zoho.eu"
smtp_port = 465
smtp_user = "noreply@furberia.org"
smtp_pass = os.getenv("MAIL_PASS")
from_email = "Comunicaciones de El Plan <noreply@elplanmadrid.org>"

dbconfig = {
    "host": DB_HOST,
    "user": DB_USER,
    "password": DB_PASSWORD,
    "database": DB_NAME,
    "port": DB_PORT,
    "charset": "utf8mb4",
    "collation": "utf8mb4_general_ci",
}

pool = pooling.MySQLConnectionPool(
    pool_name="mypool",
    pool_size=5,  # Número de conexiones en el pool
    **dbconfig,
)


class DatabaseContext:
    def __init__(self):
        self.conn = pool.get_connection()  # Obtiene una conexión del pool
        self.cursor = self.conn.cursor()  # Crea un cursor

    def __enter__(self):
        return self.conn, self.cursor  # Devuelve la conexión y el cursor

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cursor.close()  # Cierra el cursor
        self.conn.close()  # Cierra la conexión


# Funciones Auxiliares
def generate_token(email):
    try:
        expiry = datetime.now(timezone.utc) + timedelta(days=TOKEN_EXPIRY_DAYS)
        info = {"email": email, "exp": expiry}
        return jwt.encode(info, SECRET_KEY, algorithm=ALGORITHM)
    except Exception as e:
        logging.error(f"Error generating token: {e}")
        return None


def verificar_token(token):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = data["email"]

        try:
            valid = validate_email(email)
            email = valid.email
        except EmailNotValidError:
            return "Email no válido", None

        with DatabaseContext() as (conn, cursor):
            cursor.execute("SELECT COUNT(*) FROM usuarios WHERE email = %s", (email,))
            res = cursor.fetchone()
            if res is None or res[0] == 0:
                return "Usuario no existe", None

        return "Token válido", email

    except jwt.ExpiredSignatureError:
        return "Token expirado", None
    except jwt.InvalidTokenError:
        return "Token inválido", None
    except Exception as e:
        logging.error(f"Error al verificar token: {e}")
        return "Error en verificación", None


def estandarizar_telegram(tg):
    if tg.startswith("@"):
        tg = tg[1:]
    return "@" + tg


def is_allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {
        "jpg",
        "jpeg",
        "png",
    }


def encrypt_data(data, key):
    cipher = AES.new(key, AES.MODE_CFB)
    iv = cipher.iv
    ciphertext = cipher.encrypt(data.encode("utf-8"))
    return base64.b64encode(iv + ciphertext).decode("utf-8")


def decrypt_data(data, key):
    data = base64.b64decode(data)
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CFB, iv=iv)
    return cipher.decrypt(ciphertext).decode("utf-8")


def generate_recovery_code():
    # Letras y números que NO se confunden visualmente
    chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # Sin O, I, 0, 1
    return "".join(random.choices(chars, k=6)).upper()


# Rutas de la API
@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.get_json()
        email = data["email"]
        password = data["password"]
        num1 = data["num1"]
        num2 = data["num2"]
        captchaAnswer = data["captchaAnswer"]

        with DatabaseContext() as (conn, cursor):
            if not conn:
                return jsonify({"error": "No se pudo conectar a la base de datos"}), 500

            if num1 + num2 != int(captchaAnswer):
                return jsonify({"error": "Captcha incorrecto"}), 403

            cursor.execute(
                "SELECT usuarios_int.contrasena "
                "FROM usuarios_int "
                "JOIN usuarios ON usuarios.userid = usuarios_int.userid "
                "WHERE usuarios.email = %s",
                (email,),
            )
            result = cursor.fetchone()
            if result:
                correcto = bcrypt.checkpw(password.encode(), result[0])
                if correcto:
                    token = generate_token(email)
                    if token is None:
                        return jsonify(
                            {"error": "Error durante el generado del token"}
                        ), 500
                    return jsonify({"token": token}), 200
                else:
                    return jsonify({"error": "Credenciales no válidas"}), 401
            else:
                return jsonify({"error": "Usuario y/o contraseña no válidos"}), 404
    except Exception as e:
        logging.error(f"Error in login: {e}")
        return jsonify({"error": f"Error en back {e}"}), 500


def is_valid_telegram_handle(handle: str) -> bool:
    TELEGRAM_REGEX = re.compile(r"^[a-zA-Z](?:[a-zA-Z0-9_]{3,30}[a-zA-Z0-9])?$")
    return TELEGRAM_REGEX.match(handle) is not None


@app.route("/registro", methods=["POST"])
def registro():
    """ "email": "",
    "username": "",
    "password": "",
    "nacimiento": "",
    "telegram": "","""

    try:
        data = request.get_json()
        required_fields = ["email", "username", "password", "nacimiento", "telegram"]
        telegram = data["telegram"]
        if telegram.startswith("@"):
            telegram = telegram[1:]

        if any(not data.get(field, "").strip() for field in required_fields):
            return jsonify({"error": "Todos los campos son obligatorios"}), 400

        try:
            valid = validate_email(data["email"])
            email = valid.email
        except EmailNotValidError:
            return jsonify({"error": "Formato de email no válido"}), 400

        if not is_valid_telegram_handle(telegram):
            return jsonify({"error": "Formato de telegram no válido"}), 400

        with DatabaseContext() as (conn, cursor):
            cursor.execute("SELECT COUNT(*) FROM usuarios WHERE email = %s", (email,))
            if cursor.fetchone()[0] > 0:
                return jsonify({"error": "El correo electrónico ya está en uso"}), 400

            cursor.execute(
                "SELECT COUNT(*) FROM usuarios WHERE username = %s", (data["username"],)
            )
            if cursor.fetchone()[0] > 0:
                return jsonify({"error": "El nombre de usuario ya está en uso"}), 400

            cursor.execute("SELECT MAX(userid) FROM usuarios")
            last_id = cursor.fetchone()[0]
            new_id = 1 if last_id is None else last_id + 1

            hashed_password = bcrypt.hashpw(data["password"].encode(), bcrypt.gensalt())

            # Cifrar datos sensibles
            # nombre_cifrado = encrypt_data(data['nombre'], CIPHER_KEY)
            # apellidos_cifrado = encrypt_data(data['apellidos'], CIPHER_KEY)
            nacimiento_cifrado = encrypt_data(data["nacimiento"], CIPHER_KEY)
            # telefono = encrypt_data(data.get('telefono', ''), CIPHER_KEY) if data.get('telefono') else ''
            telegram = encrypt_data(telegram, CIPHER_KEY)

            # omitido nombre_cifrado, apellido cifrado y telefono
            cursor.execute(
                "INSERT INTO usuarios (userid, nombre, apellidos, email, nacimiento, telefono, telegram, username) VALUES (%s, NULL, NULL, %s, %s, NULL, %s, %s)",
                (new_id, email, nacimiento_cifrado, telegram, data["username"]),
            )
            conn.commit()

            cursor.execute(
                "INSERT INTO usuarios_int (userid, contrasena, rol) VALUES (%s, %s, %s)",
                (new_id, hashed_password, "1"),
            )
            conn.commit()

            token = generate_token(email)
            if token is None:
                return jsonify({"error": "Error durante el generado del token"}), 500
            return jsonify({"token": token}), 200
    except Exception as e:
        logging.error(f"Error in registro: {e}")
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/datos", methods=["POST"])
def datos():
    try:
        token = request.get_json()["token"]
        msj, email = verificar_token(token)

        if email is None:
            return jsonify({"error": msj}), 401

        with DatabaseContext() as (conn, cursor):
            cursor.execute(
                "SELECT userid, email, nacimiento, telegram, username FROM usuarios WHERE email = %s;",
                (email,),
            )
            info = cursor.fetchone()
            if info:
                telegram = decrypt_data(info[3], CIPHER_KEY)
                if telegram.startswith("@"):
                    telegram = telegram[1:]

                data = {
                    # "nombre": decrypt_data(info[1], CIPHER_KEY),
                    # "apellidos": decrypt_data(info[2], CIPHER_KEY),
                    "email": info[1],
                    "nacimiento": decrypt_data(info[2], CIPHER_KEY),
                    # "telefono": decrypt_data(info[5], CIPHER_KEY) if info[5] else "-",
                    "telegram": telegram,
                    "username": info[4],
                    "rol": "1",
                }
                cursor.execute(
                    "SELECT rol FROM usuarios_int WHERE userid = %s;", (info[0],)
                )
                rol = cursor.fetchone()
                if rol and rol[0] != "1":
                    data["rol"] = rol[0]
                return jsonify(data), 200
            else:
                return jsonify({"error": "Información no encontrada"}), 404
    except Exception as e:
        logging.error(f"Error in datos: {e}")
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/imagen_perfil", methods=["POST"])
def perfil_imagen():
    try:
        token = request.get_json()["token"]
        carpeta_perfiles = "/mnt/event_images/perfil"

        msj, email = verificar_token(token)

        if email is None:
            return jsonify({"error": msj}), 404

        with DatabaseContext() as (conn, cursor):
            cursor.execute("SELECT userid FROM usuarios WHERE email = %s;", (email,))
            userid = cursor.fetchone()[0]

        extensiones = ["png", "jpg", "jpeg"]
        for extension in extensiones:
            filename = f"{userid}.{extension}"
            filepath = os.path.join(carpeta_perfiles, filename)
            if os.path.exists(filepath):
                return send_from_directory(carpeta_perfiles, filename), 200

        # Si no se encuentra la imagen personalizada, devolver la imagen por defecto
        return send_from_directory("/mnt/event_images", "default_profile.png"), 200

    except Exception as e:
        logging.error(f"Error en perfil_imagen: {e}")
        return jsonify({"error": f"Error al obtener la imagen: {e}"}), 500


@app.route("/qr", methods=["POST"])
def qr():
    try:
        token = request.get_json()["token"]
        msj, email = verificar_token(token)

        if email is None:
            return jsonify({"error": msj}), 404

        with DatabaseContext() as (conn, cursor):
            cursor.execute("SELECT userid FROM usuarios WHERE email = %s;", (email,))
            userid = cursor.fetchone()[0]

            cursor.execute(
                "SELECT entradas.event_id, entradas.entrada_id, eventos.nombre, eventos.fecha_inicio, entradas.compra_id, eventos.localizacion, eventos.localizacionURL "
                "FROM entradas INNER JOIN eventos "
                "ON entradas.event_id = eventos.event_id "
                "WHERE entradas.userid = %s AND eventos.fecha_fin >= NOW();",
                (userid,),
            )

            data = cursor.fetchall()
            entradas = []
            for entrada in data:
                e = f"Furberia - {userid} - {entrada[0]} - {entrada[1]} - Furberia"
                e_enc = pyqrcode.create(QR_KEY.encrypt(e.encode()))
                e_img = e_enc.png_as_base64_str(scale=4)
                entradas.append(
                    {
                        "qr": e_img,
                        "nombre": entrada[2],
                        "fecha": entrada[3],
                        "compra_id": entrada[4],
                        "ubicacion": entrada[5],
                        "url": entrada[6],
                    }
                )

            return jsonify({"entradas": entradas}), 200
    except Exception as e:
        logging.error(f"Error in qr: {e}")
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/validarqr", methods=["POST"])
def validarqr():
    try:
        data = request.get_json()["texto"]
        try:
            texto = QR_KEY.decrypt(data).decode("utf-8")
        except Exception:
            return jsonify({"error": "QR no válido"}), 403

        ids = texto.split(" - ")[1:4]
        userid, eventid, entradaid = map(int, ids)

        with DatabaseContext() as (conn, cursor):
            cursor.execute(
                "SELECT validada FROM entradas WHERE entrada_id = %s", (entradaid,)
            )
            entrada = cursor.fetchall()
            if entrada is not None:
                if not entrada[0][0]:
                    cursor.execute(
                        "SELECT username, telegram, nacimiento, userid FROM usuarios WHERE userid = %s",
                        (userid,),
                    )
                    usuario = cursor.fetchone()
                    if usuario:
                        username = usuario[0]
                        telegram_descifrado = (
                            decrypt_data(usuario[1], CIPHER_KEY) if usuario[1] else "-"
                        )
                        nacimiento_descrifrado = decrypt_data(usuario[2], CIPHER_KEY)
                        userid = usuario[3]
                    else:
                        return jsonify({"error": "Usuario no encontrado"}), 404

                    cursor.execute(
                        "SELECT nombre, fecha_inicio FROM eventos WHERE event_id = %s",
                        (eventid,),
                    )
                    evento = cursor.fetchone()

                    if evento:
                        res = {
                            "entrada_id": entradaid,
                            "username": username,
                            "telegram": telegram_descifrado,
                            "nacimiento": nacimiento_descrifrado,
                            "evento_id": eventid,
                            "evento": evento[0],
                            "fecha": evento[1],
                            "userid": userid,
                        }
                        return jsonify({"res": res}), 200
                    else:
                        return jsonify({"error": "Evento no encontrado"}), 404
                else:
                    return jsonify({"error": "Entrada ya validada"}), 409
            else:
                return jsonify({"error": "Entrada no encontrada"}), 404
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/fotoqr", methods=["POST"])
def fotoqr():
    data = request.get_json()
    token = data["token"]
    userid = data["userid"]

    msj, email = verificar_token(token)

    carpeta_perfiles = "/mnt/event_images/perfil"

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        rol = obtener_rol(email)
        if rol > 1:
            extensiones = ["png", "jpg", "jpeg"]
            for extension in extensiones:
                filename = f"{userid}.{extension}"
                filepath = os.path.join(carpeta_perfiles, filename)
                if os.path.exists(filepath):
                    return send_from_directory(carpeta_perfiles, filename), 200
            return jsonify({"mensaje": "No foto disponible"}), 244
        return jsonify({"error": "No autorizado"}), 400
    except Exception as e:
        logging.error(f"Error en perfil_imagen: {e}")
        return jsonify({"error": f"Error al obtener la imagen: {e}"}), 500


def obtener_telegram(email=None, id=None):
    hayid = False
    if email is None and id is None:
        return "-"
    if id is not None:
        hayid = True
        dato = id
    else:
        dato = email
    with DatabaseContext() as (conn, cursor):
        if hayid:
            cursor.execute("SELECT telegram FROM usuarios WHERE userid = %s", (dato,))
        else:
            cursor.execute("SELECT telegram FROM usuarios WHERE email = %s", (dato,))
        info = cursor.fetchone()[0]
    return decrypt_data(info, CIPHER_KEY)


def obtener_username(email=None, id=None):
    hayid = False
    if email is None and id is None:
        return "-"
    if id is not None:
        hayid = True
        dato = id
    else:
        dato = email
    with DatabaseContext() as (conn, cursor):
        if hayid:
            cursor.execute("SELECT username FROM usuarios WHERE userid = %s", (dato,))
        else:
            cursor.execute("SELECT username FROM usuarios WHERE email = %s", (dato,))
        info = cursor.fetchone()[0]
    return info


@app.route("/aceptar", methods=["POST"])
def aceptar():
    datos = request.get_json()
    print(datos)
    entrada = datos["entrada"]
    token_ejecutor = datos["token"]
    receptor = datos["receptor"]
    evento = datos["evento"]
    with DatabaseContext() as (conn, cursor):
        try:
            msj, email = verificar_token(token_ejecutor)

            if email is None:
                return jsonify({"error": msj}), 401

            rol_ejecutor = obtener_rol(email)
            id_ejecutor = obtener_id(email)
            t_e = obtener_telegram(email=email)
            u_e = obtener_username(email=email)
            t_r = obtener_telegram(id=receptor)
            u_r = obtener_username(id=receptor)

            if rol_ejecutor > 1:
                cursor.execute(
                    "UPDATE entradas SET validada = true WHERE entradas.entrada_id = %s",
                    (entrada,),
                )
                conn.commit()

                cursor.execute(
                    "INSERT INTO log (ejecutor, receptor, evento, accion, comentarios) VALUES (%s, %s, %s, %s, %s)",
                    (
                        id_ejecutor,
                        receptor,
                        evento,
                        "Aceptar",
                        f"{u_e} ({estandarizar_telegram(t_e)}) acepta entarda de {u_r} ({estandarizar_telegram(t_r)})",
                    ),
                )
                conn.commit()
                return "OK", 200
            else:
                return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
        except Exception as e:
            logging.error(f"Error in aceptar: {e}")
            conn.rollback()
            return jsonify(
                {"error": "Error en la base de datos", "detalle": str(e)}
            ), 500


@app.route("/username", methods=["POST"])
def username():
    try:
        token = request.get_json()["token"]
        msj, email = verificar_token(token)

        if email is None:
            return jsonify({"error": msj}), 401

        with DatabaseContext() as (conn, cursor):
            cursor.execute(
                "SELECT usuarios.username FROM usuarios WHERE email = %s;", (email,)
            )
            info = cursor.fetchone()
            if info:
                data = {"username": info[0]}
                return jsonify(data), 200
            else:
                return jsonify({"error": "Username no encontrado"}), 404
    except Exception as e:
        logging.error(f"Error in username: {e}")
        return jsonify({"error": f"Error en back: {e}"}), 502


@app.route("/upload", methods=["POST"])
def upload_image():
    try:
        token = request.form.get("token")
        msj, email = verificar_token(token)

        if email is None:
            return jsonify({"error": msj}), 401

        if "imagen" not in request.files:
            return jsonify({"error": "No se encontró ninguna imagen"}), 400

        imagen = request.files["imagen"]
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer(imagen.read(2048))
        imagen.seek(0)  # Resetear el puntero del archivo después de leer

        if imagen.content_length > 5 * 1024 * 1024:  # 5 MB
            return jsonify(
                {"error": "El tamaño de la imagen no puede exceder los 5 MB"}
            ), 440

        if mime_type not in ["image/jpeg", "image/png", "image/jpg"]:
            return jsonify(
                {
                    "error": "Formato de archivo no permitido. Solo se permiten archivos PNG, JPG o JPEG."
                }
            ), 400

        # Obtener extensión de la imagen
        extension = ""
        if mime_type == "image/jpeg" or mime_type == "image/jpg":
            extension = "jpg"
        elif mime_type == "image/png":
            extension = "png"

        # Obtener el userid del usuario
        with DatabaseContext() as (conn, cursor):
            cursor.execute("SELECT userid FROM usuarios WHERE email = %s", (email,))
            result = cursor.fetchone()

            if not result:
                return jsonify({"error": "Usuario no encontrado"}), 404

            userid = result[0]

        # Definir la ruta del archivo
        carpeta_perfiles = "/mnt/event_images/perfil"  # Asegúrate de que esta ruta es correcta y tiene permisos de escritura
        filename = f"{userid}.{extension}"
        filepath = os.path.join(carpeta_perfiles, filename)

        for ext in ["jpg", "jpeg", "png"]:
            old_filepath = os.path.join(carpeta_perfiles, f"{userid}.{ext}")
            if os.path.exists(old_filepath):
                os.remove(old_filepath)

        # Guardar la imagen, reemplazando si ya existe
        imagen.save(filepath)

        return jsonify(
            {"mensaje": "Imagen subida exitosamente", "imagen": filename}
        ), 200
    except Exception as e:
        logging.error(f"Error in upload_image: {e}")
        return jsonify({"error": f"Error al subir la imagen: {e}"}), 500


@app.route("/updateDatos", methods=["POST"])
def updateDatos():
    info = request.get_json()
    token = info.get("token")

    msj, email = verificar_token(token)
    if email is None:
        return jsonify({"error": msj}), 401

    user_id = obtener_id(email)

    with DatabaseContext() as (conn, cursor):
        # Lista de campos permitidos
        # añadir mas adelante nombre, apellidos y telefono
        campos_permitidos = {"username", "nacimiento", "telegram"}

        # Filtrar y construir el diccionario de campos
        campos = {k: v for k, v in info.items() if k in campos_permitidos and v}

        u_e = obtener_username(id=user_id)
        t_e = obtener_telegram(id=user_id)

        try:
            # Verificar si el nombre de usuario ya existe
            if "username" in campos:
                cursor.execute(
                    "SELECT COUNT(*) FROM usuarios WHERE username = %s AND email != %s",
                    (campos["username"], email),
                )
                if cursor.fetchone()[0] > 0:
                    return jsonify({"error": "Nombre de usuario ya en uso"}), 403
            # Cifrar los datos sensibles
            # meter nombre, apellidos y telefono mas adelante
            for campo in ["nacimiento", "telegram"]:
                if campo in campos:
                    campos[campo] = encrypt_data(campos[campo], CIPHER_KEY)

            # Construir la consulta de actualización dinámicamente
            update_query = "UPDATE usuarios SET "
            update_values = []
            for campo, valor in campos.items():
                update_query += f"{campo} = %s, "
                update_values.append(valor)
                cursor.execute(
                    "INSERT INTO log (ejecutor, accion, comentarios) VALUES (%s, %s, %s)",
                    (
                        user_id,
                        "EInformacion",
                        f"{u_e} ({estandarizar_telegram(t_e)}) cambio su {campo}",
                    ),
                )
                conn.commit()

            # Quitar la última coma y espacio
            update_query = update_query.rstrip(", ")
            update_query += " WHERE email = %s"
            update_values.append(email)

            # Ejecutar la consulta de actualización
            cursor.execute(update_query, tuple(update_values))
            conn.commit()

            return "OK", 200
        except Exception as e:
            logging.error(f"Error in updateDatos: {e}")
            conn.rollback()
            return jsonify({"error": f"Error en la actualización de datos: {e}"}), 500


@app.route("/updatePassword", methods=["POST"])
def updatePassword():
    info = request.get_json()
    token = info["token"]
    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    with DatabaseContext() as (conn, cursor):
        old_password = info["old_password"]
        new_password = info["new_password"]

        cursor.execute(
            "SELECT usuarios_int.contrasena FROM usuarios_int join usuarios on usuarios.userid = usuarios_int.userid WHERE usuarios.email= %s",
            (email,),
        )

        result = cursor.fetchone()[0]

        correcto = bcrypt.checkpw(old_password.encode(), result)

        if correcto:
            hashed_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
            try:
                cursor.execute(
                    "UPDATE usuarios_int SET contrasena = %s WHERE userid = (SELECT userid FROM usuarios WHERE email = %s)",
                    (hashed_password, email),
                )
                conn.commit()
                return "OK", 200
            except Exception as e:
                logging.error(f"Error in updatePassword: {e}")
                conn.rollback()
                return jsonify(
                    {"error": f"Error en la actualización de la contraseña: {e}"}
                ), 500
        else:
            return jsonify({"error": "Credenciales no válidas"}), 401


@app.route("/borrarCuenta", methods=["POST"])
def borrarCuenta():
    cuenta = request.get_json()

    msj, email = verificar_token(cuenta["token"])

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        with DatabaseContext() as (conn, cursor):
            password = cuenta["password"]

            cursor.execute(
                "SELECT usuarios_int.contrasena FROM usuarios_int join usuarios on usuarios.userid = usuarios_int.userid WHERE usuarios.email= %s",
                (email,),
            )

            result = cursor.fetchone()[0]

            correcto = bcrypt.checkpw(password.encode(), result)

            if correcto:
                user_id = obtener_id(email)
                cursor.execute(
                    "SELECT username, telegram FROM usuarios WHERE userid = %s",
                    (user_id,),
                )
                data = cursor.fetchone()
                username = data[0]
                telegram = decrypt_data(data[1], CIPHER_KEY)
                cursor.execute(
                    "SELECT e.nombre, e.fecha_inicio FROM entradas en JOIN eventos e ON en.event_id = e.event_id WHERE en.userid = %s  AND e.fecha_fin > NOW();",
                    (user_id,),
                )
                info = cursor.fetchall()
                comentario = "Entradas perdidas: "

                entradas_perdidas = False
                for dato in info:
                    entradas_perdidas = True
                    comentario = comentario + f"{dato[0]} ({dato[1]}), "
                if not entradas_perdidas:
                    comentario = "No ha perdido entradas"
                comentario = (
                    f"{username} ({estandarizar_telegram(telegram)}) se ha borado la cuenta. "
                    + comentario.rstrip(", ")
                )
                cursor.execute(
                    "INSERT INTO log (ejecutor, accion, comentarios) VALUES (%s, %s, %s)",
                    (
                        user_id,
                        "BorrarCuenta",
                        comentario,
                    ),
                )
                conn.commit()
                cursor.execute("DELETE FROM usuarios WHERE email = %s", (email,))
                conn.commit()
                return "OK", 200
            else:
                return jsonify({"error": "Contraseña incorrecta"}), 401
    except Exception as e:
        logging.error(f"Error in borrarCuenta: {e}")
        return jsonify({"error": f"{e}"}), 500


@app.route("/imagenes/<int:event_id>", methods=["GET"])
def obtener_imagenes(event_id):
    try:
        event_dir = os.path.join(EVENT_DIR, str(event_id))

        if not os.path.exists(event_dir):
            return jsonify({"error": "Evento no encontrado"}), 404

        images = [f for f in os.listdir(event_dir) if is_allowed_file(f)]
        num_images = len(images)

        return jsonify({"evento": event_id, "imagenes": num_images}), 200
    except Exception as e:
        logging.error(f"Error in obtener_imagenes: {e}")
        return jsonify({"error": f"Error durante la obtencion de imagenes: {e}"}), 500


@app.route("/imagenes/<int:event_id>/<filename>", methods=["GET"])
def servir_imagen(event_id, filename):
    try:
        # Sanitiza el nombre del archivo
        filename = secure_filename(filename)

        if not is_allowed_file(filename):
            abort(404, description="Recurso no encontrado")

        event_directory = os.path.join(EVENT_DIR, str(event_id))
        print(event_directory)

        # Verifica que el archivo existe antes de servirlo
        file_path = os.path.join(event_directory, filename)
        if not os.path.isfile(file_path):
            abort(404, description="Recurso no encontrado")

        response = make_response(send_from_directory(event_directory, filename))
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"

        return response
    except FileNotFoundError:
        abort(404, description="Recurso no encontrado")
    except Exception as e:
        logging.error(f"Error in servir_imagen: {e}")
        return jsonify({"error": f"Error al servir la imagen: {e}"}), 500


def obtener_rol(email):
    with DatabaseContext() as (conn, cursor):
        cursor.execute(
            "SELECT rol FROM usuarios_int JOIN usuarios ON usuarios.userid=usuarios_int.userid WHERE email= %s",
            (email,),
        )
        rol = cursor.fetchone()
        return rol[0]


@app.route("/rol", methods=["POST"])
def rol():
    cuenta = request.get_json()

    msj, email = verificar_token(cuenta["token"])

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        rol = obtener_rol(email)

        if rol:
            return jsonify({"rol": rol}), 200
        else:
            return jsonify({"error": "Usuario no encontrado"}), 404

    except Exception as e:
        logging.error(f"Error en rol: {e}")
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/usuarios", methods=["POST"])
def obtener_usuarios():
    token = request.get_json()["token"]
    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        rol = obtener_rol(email)
        if rol > 1:
            with DatabaseContext() as (conn, cursor):
                cursor.execute("SELECT userid, username, telegram FROM usuarios")
                data = cursor.fetchall()
                usuarios = []
                for elem in data:
                    telegram = decrypt_data(elem[2], CIPHER_KEY)
                    if telegram.startswith("@"):
                        telegram = telegram[1:]
                    usuarios.append(
                        {"id": elem[0], "username": elem[1], "telegram": telegram}
                    )
                return jsonify({"usuarios": usuarios}), 200
        else:
            return jsonify({"error": "Usuario no autorizado a esta peticion"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/eventos", methods=["POST"])
def obtener_eventos():
    info = request.get_json()
    token = info["token"]
    todos = info["all"]
    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    if not isinstance(todos, bool):
        todos = bool(todos)

    try:
        rol = obtener_rol(email)
        if todos:
            if rol > 2:
                with DatabaseContext() as (conn, cursor):
                    cursor.execute("SELECT event_id, nombre, fecha_inicio FROM eventos")
                    data = cursor.fetchall()
                    eventos = []
                    for elem in data:
                        id = elem[0]
                        nombre = elem[1]
                        fecha = elem[2]
                        evento = {"id": id, "nombre": nombre, "fecha": fecha}
                        eventos.append(evento)
                    return jsonify({"eventos": eventos}), 200
            else:
                return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
        else:
            if rol > 1:
                with DatabaseContext() as (conn, cursor):
                    cursor.execute(
                        "SELECT event_id, nombre, fecha_inicio FROM eventos WHERE fecha_fin >= NOW()"
                    )
                    data = cursor.fetchall()
                    eventos = []
                    for elem in data:
                        cursor.execute(
                            "SELECT aforo from eventos_int WHERE event_id = %s",
                            (elem[0],),
                        )
                        aforo = cursor.fetchone()[0]
                        id = elem[0]
                        nombre = elem[1]
                        fecha = elem[2]
                        asistentes = []
                        cursor.execute(
                            "SELECT userid FROM entradas WHERE event_id = %s", (id,)
                        )
                        indata = cursor.fetchall()
                        for inelem in indata:
                            asistentes.append(inelem[0])
                        evento = {
                            "id": id,
                            "nombre": nombre,
                            "fecha": fecha,
                            "asistentes": asistentes,
                            "aforo": aforo,
                        }
                        eventos.append(evento)
                    return jsonify({"eventos": eventos}), 200
            else:
                return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


def get_compra_id(evento):
    try:
        with DatabaseContext() as (conn, cursor):
            cursor.execute(
                "SELECT compra_id FROM entradas WHERE event_id = %s ORDER BY compra_id DESC LIMIT 1",
                (evento,),
            )
            compra = cursor.fetchone()
            return compra[0] if compra else 0
    except Exception as e:
        return jsonify({"error": f"Error en get_compra_id: {e}"}), 404


def obtener_id(email):
    try:
        with DatabaseContext() as (conn, cursor):
            cursor.execute("SELECT userid FROM usuarios WHERE email = %s", (email,))
            id = cursor.fetchone()
            return id[0] if id else 0
    except Exception:
        return -1


@app.route("/otorgar_entrada", methods=["POST"])
def otorgar_entrada():
    datos = request.get_json()
    usuario = datos["usuario"]
    evento = datos["evento"]
    token = datos["token"]
    metodo = datos["metodo"]

    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    valid_methods = {"paypal", "bizum", "transferencia"}

    if metodo not in valid_methods:
        return jsonify({"error": "método de pago no válido"}), 403

    with DatabaseContext() as (conn, cursor):
        cursor.execute("SELECT 1 FROM eventos WHERE event_id = %s", (evento,))
        if cursor.fetchone() is None:
            return jsonify({"error": "Evento no encontrado"}), 404
        cursor.execute(
            "SELECT 1 FROM entradas WHERE userid = %s AND event_id = %s",
            (
                usuario,
                evento,
            ),
        )
        if cursor.fetchone() is not None:
            return jsonify({"error": "Entrada ya existente"}), 409

    try:
        rol = obtener_rol(email)
        approver = obtener_id(email)
        if (rol > 1) and (approver != -1):
            compra_id = get_compra_id(evento)
            with DatabaseContext() as (conn, cursor):
                cursor.execute(
                    "INSERT INTO entradas (userid, event_id, validada, compra_id, approver, metodo) VALUES (%s, %s, 0, %s, %s, %s)",
                    (usuario, evento, compra_id + 1, approver, metodo),
                )
                conn.commit()
                u_e = obtener_username(id=approver)
                t_e = obtener_telegram(id=approver)
                u_r = obtener_username(id=usuario)
                t_r = obtener_telegram(id=usuario)
                cursor.execute(
                    "INSERT INTO log (ejecutor, receptor, evento, accion, comentarios) VALUES (%s, %s, %s, %s, %s)",
                    (
                        approver,
                        usuario,
                        evento,
                        "Otorgar",
                        f"{u_e} ({estandarizar_telegram(t_e)}) otorga entrada a {u_r} ({estandarizar_telegram(t_r)})",
                    ),
                )
                conn.commit()
                return "OK", 200
        else:
            return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/revocar_entrada", methods=["POST"])
def revocar_entrada():
    datos = request.get_json()
    token = datos["token"]
    usuario = datos["usuario"]
    evento = datos["evento"]

    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    with DatabaseContext() as (conn, cursor):
        cursor.execute(
            "SELECT 1 FROM entradas WHERE event_id = %s AND userid = %s",
            (
                evento,
                usuario,
            ),
        )
        if cursor.fetchone() is None:
            return jsonify({"error": "Entrada no encontrada"}), 404

    try:
        rol = obtener_rol(email)
        if rol > 2:
            with DatabaseContext() as (conn, cursor):
                cursor.execute(
                    "DELETE FROM entradas WHERE userid = %s AND event_id = %s",
                    (
                        usuario,
                        evento,
                    ),
                )
                conn.commit()
                id_e = obtener_id(email)
                u_e = obtener_username(email=email)
                t_e = obtener_telegram(email=email)
                u_r = obtener_username(id=usuario)
                t_r = obtener_telegram(id=usuario)
                cursor.execute(
                    "INSERT INTO log (ejecutor, receptor, evento, accion, comentarios) VALUES (%s, %s, %s, %s, %s)",
                    (
                        id_e,
                        usuario,
                        evento,
                        "Revocar",
                        f"{u_e} ({estandarizar_telegram(t_e)}) revoca entrada a {u_r} ({estandarizar_telegram(t_r)})",
                    ),
                )
                conn.commit()
                return "OK", 200
        else:
            return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/cuentas", methods=["POST"])
def cuentas():
    data = request.get_json()
    token = data["token"]
    evento = data["evento"]

    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        rol = obtener_rol(email)
        if rol == 3:
            with DatabaseContext() as (conn, cursor):
                cursor.execute(
                    """SELECT
                            usuarios.username,
                            SUM(CASE WHEN metodo = 'paypal' THEN 1 ELSE 0 END) AS paypal,
                            SUM(CASE WHEN metodo = 'bizum' THEN 1 ELSE 0 END) AS bizum,
                            SUM(CASE WHEN metodo = 'transferencia' THEN 1 ELSE 0 END) AS transferencia,
                            SUM(CASE WHEN metodo = 'gratuito' THEN 1 ELSE 0 END) AS gratuito
                            FROM entradas JOIN usuarios ON entradas.approver = usuarios.userid
                            WHERE event_id = %s GROUP BY usuarios.username;""",
                    (evento,),
                )
                datos = cursor.fetchall()
                approvers = []
                for elem in datos:
                    usuario = {
                        "usuario": elem[0],
                        "paypal": int(elem[1]),
                        "bizum": int(elem[2]),
                        "transferencia": int(elem[3]),
                        "gratuito": int(elem[4]),
                    }
                    approvers.append(usuario)
                cursor.execute(
                    "SELECT precio_base FROM eventos WHERE event_id = %s", (evento,)
                )
                precio = cursor.fetchone()[0]
                return jsonify({"precio": precio, "approvers": approvers}), 200
        else:
            return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


def enviarcorreo(email, codigo):
    # Configura el correo de recuperación
    subject = "Tu código de recuperación / Your recovery code"
    correo = "./recuperacion.html"

    # Abre el archivo HTML del correo
    with open(correo, "r", encoding="utf-8") as file:
        content = file.read()

    # Sustituye el marcador de posición en el HTML por el código
    content = content.replace("-cod-", codigo)

    # Crea el objeto del correo
    mail = MIMEMultipart("related")
    mail["Subject"] = subject
    mail["From"] = from_email
    mail["To"] = email

    # Adjunta el cuerpo HTML
    html_body = MIMEText(content, "html", "utf-8")
    mail.attach(html_body)

    # Adjuntar la imagen
    with open("./Nombre.png", "rb") as img:
        logo_img = MIMEImage(img.read())
        logo_img.add_header("Content-ID", "<logo_image>")
        mail.attach(logo_img)

    try:
        # Inicia el servidor SMTP
        print(f"🔐 smtp_pass en enviarcorreo: {repr(smtp_pass)}")
        server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        server.login(smtp_user, smtp_pass)
        server.sendmail(from_email, email, mail.as_string())
        return "OK", 200
    except Exception as e:
        return str(e), 500
    finally:
        try:
            server.quit()
        except NameError:
            pass


@app.route("/mailrecovery", methods=["POST"])
def recovery():
    data = request.get_json()
    email = data.get("email")

    if not email:
        return jsonify({"error": "Email es requerido"}), 400

    with DatabaseContext() as (conn, cursor):
        try:
            # Obtener el userid de la tabla usuarios
            cursor.execute("SELECT userid FROM usuarios WHERE email = %s", (email,))
            result = cursor.fetchone()

            if not result:
                return jsonify(
                    {"error": "Email no encontrado en la tabla usuarios"}
                ), 404

            userid = result[0]

            # Obtener la fecha y hora actual
            fecha_actual = datetime.now()

            # Verificar si ya hay un código de recuperación no expirado
            cursor.execute(
                "SELECT codigo_recuperacion, expiracionrecovery FROM usuarios_int WHERE userid = %s",
                (userid,),
            )
            fila = cursor.fetchone()

            if fila:
                codigo, expiracion = fila
                if codigo and expiracion and expiracion > fecha_actual:
                    return jsonify(
                        {"mensaje": "Ya hay un código de recuperación válido"}
                    ), 409

            # Generar un nuevo código de recuperación
            codigo = generate_recovery_code()

            # Cifrar el código antes de almacenarlo
            codigo_hash = bcrypt.hashpw(codigo.encode(), bcrypt.gensalt()).decode()
            if os.getenv("FLASK_ENV") == "testing":
                fecha_expiracion = fecha_actual + timedelta(seconds=3)
            else:
                fecha_expiracion = fecha_actual + timedelta(minutes=15)

            # Insertar o actualizar el código de recuperación y su fecha de expiración
            cursor.execute(
                """UPDATE usuarios_int SET codigo_recuperacion = %s, expiracionrecovery = %s WHERE userid = %s""",
                (codigo_hash, fecha_expiracion, userid),
            )
            conn.commit()

            # Enviar el correo con el código
            res, res_code = enviarcorreo(email, codigo)

            if res != "OK":
                return jsonify({"error": res}), res_code

            if os.getenv("FLASK_ENV") == "testing":
                return jsonify(
                    {
                        "mensaje": "Código de recuperación enviado correctamente",
                        "codigo": codigo,
                    }
                ), 200

            return jsonify(
                {"mensaje": "Código de recuperación enviado correctamente"}
            ), 200

        except Exception as e:
            return jsonify({"error": str(e)}), 500


@app.route("/recover_password", methods=["POST"])
def recover_password():
    info = request.get_json()
    email = info.get("email")
    password = info.get("password")
    code = info.get("code")

    if not all([email, password, code]):
        return jsonify({"error": "Faltan datos"}), 400

    with DatabaseContext() as (conn, cursor):
        try:
            # Obtener el usuario por email
            cursor.execute("SELECT userid FROM usuarios WHERE email = %s", (email,))
            result = cursor.fetchone()
            if not result:
                return jsonify({"error": "Email no encontrado"}), 404

            userid = result[0]

            # Obtener el código de recuperación y la fecha de expiración
            cursor.execute(
                "SELECT codigo_recuperacion, expiracionrecovery FROM usuarios_int WHERE userid = %s",
                (userid,),
            )
            data = cursor.fetchone()
            if not data:
                return jsonify(
                    {"error": "No se encontraron datos de recuperación"}
                ), 404

            codigo_guardado, expiracion = data

            # Verificar si el código ha expirado
            if expiracion < datetime.now():
                return jsonify({"error": "Código expirado"}), 403

            # Verificar si el código ingresado coincide con el código guardado en la base de datos
            if not bcrypt.checkpw(code.upper().encode(), codigo_guardado.encode()):
                return jsonify({"error": "Código inválido"}), 403

            # Si el código es válido, actualizar la contraseña
            new_pass = bcrypt.hashpw(password.encode(), bcrypt.gensalt())

            # Actualizar la contraseña y limpiar el código de recuperación
            cursor.execute(
                "UPDATE usuarios_int SET contrasena = %s, codigo_recuperacion = NULL, expiracionrecovery = NULL WHERE userid = %s",
                (new_pass, userid),
            )
            conn.commit()

            return jsonify({"message": "Contraseña modificada con éxito"}), 200

        except Exception as e:
            logging.error(f"Error en recover_password: {e}")
            conn.rollback()
            return jsonify({"error": "Error al actualizar la base de datos"}), 500


@app.route("/entradas_otorgadas", methods=["POST"])
def entradas_otorgadas():
    data = request.get_json()
    token = data["token"]
    evento = data["evento"]

    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        rol = obtener_rol(email)
        if rol == 3:
            with DatabaseContext() as (conn, cursor):
                cursor.execute(
                    "SELECT usuarios.username, usuarios.telegram, approvers.username FROM furberia.entradas join usuarios on usuarios.userid = entradas.userid JOIN usuarios as approvers on approvers.userid = entradas.approver WHERE entradas.event_id = %s;",
                    (evento,),
                )
                info = cursor.fetchall()
            entradas = []
            for dato in info:
                tg_descifrado = decrypt_data(dato[1], CIPHER_KEY)
                if tg_descifrado.startswith("@"):
                    tg_descifrado = tg_descifrado[1:]
                entrada = {
                    "usuario": dato[0],
                    "telegram": tg_descifrado,
                    "approver": dato[2],
                }
                entradas.append(entrada)
            return jsonify({"entradas": entradas}), 200
        else:
            return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/exportar_cuentas", methods=["POST"])
def export_cuentas():
    data = request.get_json()
    token = data["token"]
    evento = data["evento"]

    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 401

    try:
        rol = obtener_rol(email)
        if rol == 3:
            with DatabaseContext() as (conn, cursor):
                cursor.execute(
                    "SELECT usuarios.username, usuarios.telegram, approvers.username, entradas.metodo "
                    "FROM furberia.entradas "
                    "JOIN usuarios ON usuarios.userid = entradas.userid "
                    "JOIN usuarios AS approvers ON approvers.userid = entradas.approver "
                    "WHERE entradas.event_id = %s;",
                    (evento,),
                )
                info = cursor.fetchall()

                # Crear un objeto StringIO para almacenar el CSV en memoria
                output = io.StringIO()
                csv_writer = csv.writer(output, delimiter=";")

                # Escribir los encabezados
                csv_writer.writerow(["Usuario", "Telegram", "Approver", "Metodo"])

                for row in info:
                    usuario = row[0]
                    telegram_encriptado = row[1]
                    approver = row[2]
                    metodo = row[3]

                    # Desencriptar el campo 'telegram'
                    tg_descifrado = decrypt_data(telegram_encriptado, CIPHER_KEY)
                    if tg_descifrado.startswith("@"):
                        tg_descifrado = tg_descifrado[1:]

                    csv_writer.writerow([usuario, tg_descifrado, approver, metodo])

                # Mover el cursor al inicio del archivo
                output.seek(0)

                # Enviar el archivo CSV como respuesta
                response = Response(
                    output.getvalue(),
                    mimetype="text/csv; charset=utf-8",
                    headers={
                        "Content-Disposition": "attachment; filename=datos_exportados.csv"
                    },
                )
                return response, 200
        else:
            return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/foto_admin", methods=["POST"])
def fotoAdmin():
    data = request.get_json()
    token = data["token"]
    usuario = data["usuario"]
    carpeta = "/mnt/event_images/perfil"
    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 404

    try:
        rol = obtener_rol(email)
        if rol > 1:
            extensiones = ["png", "jpg", "jpeg"]
            for extension in extensiones:
                filename = f"{int(usuario)}.{extension}"
                filepath = os.path.join(carpeta, filename)
                if os.path.exists(filepath):
                    return send_from_directory(carpeta, filename), 200
            return send_from_directory("/mnt/event_images", "default_profile.png"), 200

        else:
            return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


def recuperar_accion(acc):
    if acc == "EInformacion":
        return "Editar información"
    if acc == "Aceptar":
        return "Aceptar entrada"
    if acc == "BorrarCuenta":
        return "Borrar cuenta"
    if acc == "Otorgar":
        return "Otorgar entrada"
    if acc == "Revocar":
        return "Revocar entrada"
    return "-"


@app.route("/log", methods=["POST"])
def loggin():
    data = request.get_json()
    token = data["token"]
    evento = data["evento"]
    msj, email = verificar_token(token)

    if email is None:
        return jsonify({"error": msj}), 404

    try:
        with DatabaseContext() as (conn, cursor):
            rol = obtener_rol(email)
            if rol > 2:
                cursor.execute("SELECT * FROM log WHERE evento = %s", (evento,))
                logs = cursor.fetchall()
                res = []
                for log_entry in logs:
                    ejecutor = obtener_username(id=log_entry[1])
                    if log_entry[2] is not None:
                        receptor = obtener_username(id=log_entry[2])
                    else:
                        receptor = "-"
                    accion = recuperar_accion(log_entry[4])
                    r = {
                        "ejecutor": ejecutor,
                        "receptor": receptor,
                        "accion": accion,
                        "comentario": log_entry[5],
                        "fecha": log_entry[6],
                    }
                    res.append(r)
                print(res)
                return jsonify({"logs": res}), 200
            else:
                return jsonify({"error": "Usuario no autorizado a esta petición"}), 403
    except Exception as e:
        return jsonify({"error": f"Error en back: {e}"}), 500


@app.route("/health", methods=["GET"])
def health():
    return "ok", 200


if __name__ == "__main__":
    # Ejecuta la aplicación en el puerto 5001
    app.run(host="0.0.0.0", port=8000)

import json
from fastapi import FastAPI, HTTPException, File, UploadFile, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import BaseModel
from datetime import datetime, timedelta
from fastapi import BackgroundTasks
from typing import Optional
import jwt
from jwt import ExpiredSignatureError, DecodeError
import bcrypt
import os
from pathlib import Path
import shutil
import psycopg2 
from dotenv import load_dotenv

#Configuraciones, Metodos y clases a usar, asi como cargar informacion del .env

load_dotenv()
app = FastAPI()

UPLOAD_DIR = Path("uploaded_images")
UPLOAD_DIR.mkdir(exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

conf = ConnectionConfig(
    MAIL_USERNAME="donate.me.infc@gmail.com",
    MAIL_PASSWORD="duju iqcp glat eclz",
    MAIL_FROM="donate.me.infc@gmail.com",
    MAIL_PORT=587,
    MAIL_SERVER="smtp.gmail.com",
    MAIL_STARTTLS=True,
    MAIL_SSL_TLS=False,
    VALIDATE_CERTS=True
)

SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")

class User(BaseModel):
    user_name: str
    email: str
    pasword: str
    
class Donors(BaseModel):
    user_name: str
    last_name: str
    email: str
    phone_number: str
    pasword: str
    
class Center(BaseModel):
    user_name: str
    email: str
    pasword: str    
    
class LoginRequest(BaseModel):
    email: str
    password: str

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        port=os.getenv('DB_PORT')
    )

def generar_token_verificacion(email: str):
    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return token

async def enviar_correo_verificacion(email: str, token: str):
    enlace_verificacion = f"http://localhost:8000/verificar-correo?token={token}"
    mensaje = MessageSchema(
        subject="Confirma tu correo electrónico",
        recipients=[email],
        body=f"Por favor, haz clic en el siguiente enlace para confirmar tu dirección de correo: <a href='{enlace_verificacion}'>Verificar Correo</a>",
        subtype="html"
    )

    fm = FastMail(conf)
    await fm.send_message(mensaje)

#Querys y consultas sql a postgres de usuarios

@app.get("/")
def read_root():
    return {"message": "Hello world"}

@app.get("/verificar-correo")
async def verificar_correo(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload["email"]

        conn = get_db_connection()
        cursor = conn.cursor()
        sql = """
        UPDATE "users" 
        SET is_verified = TRUE 
        WHERE email = %s
        """
        cursor.execute(sql, (email,))
        conn.commit()
        cursor.close()
        conn.close()
        
        return {"message": "Correo verificado exitosamente"}
    except ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="El token ha expirado")
    except DecodeError:
        raise HTTPException(status_code=400, detail="Token inválido")

@app.post("/register")
async def register_user(
    user_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    image: Optional[UploadFile] = File(None)
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="El correo ya está registrado.")
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        image_url = None
        if image:
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/{UPLOAD_DIR}/{image.filename}"
        
        
        sql = """
        INSERT INTO users (user_name, email, pasword, is_verified, is_admin, images) 
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        values = (user_name, email, hashed_password, False, False, image_url)
        cursor.execute(sql, values)
        conn.commit()
        
        token = generar_token_verificacion(email)
        background_tasks.add_task(enviar_correo_verificacion, email, token)
        
        cursor.close()
        conn.close()
        
        return {"message": "Usuario registrado. Verifica tu correo para activar la cuenta."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
    
@app.post("/login")
def login(usr: LoginRequest):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Buscar el usuario en la tabla 'users'
        cursor.execute("SELECT * FROM \"users\" WHERE email = %s", (usr.email,))
        user_record = cursor.fetchone()
        
        if not user_record:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        
        # Verificar si el usuario ha verificado su correo electrónico
        if not user_record[4]:  
            raise HTTPException(status_code=401, detail="Verifica tu correo electrónico antes de iniciar sesión")
        
        # Verificar la contraseña
        if not bcrypt.checkpw(usr.password.encode('utf-8'), user_record[3].encode('utf-8')): 
            raise HTTPException(status_code=401, detail="Contraseña incorrecta")

        # Determinar el tipo de usuario buscando en las tablas 'donors' y 'center'
        user_type = "unknown"
        
        # Buscar en la tabla 'donors'
        cursor.execute("SELECT * FROM \"donors\" WHERE email = %s", (usr.email,))
        if cursor.fetchone():
            user_type = "donor"
        else:
            # Si no está en 'donors', buscar en la tabla 'center'
            cursor.execute("SELECT * FROM \"center\" WHERE email = %s", (usr.email,))
            if cursor.fetchone():
                user_type = "center"

        conn.close()
        
        # Generar el token JWT
        token = jwt.encode(
            {"sub": usr.email, "exp": datetime.utcnow() + timedelta(hours=1), "type": user_type},
            SECRET_KEY,
            algorithm="HS256"
        )
        
        return {"access_token": token, "token_type": "bearer", "user_type": user_type}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
   

#Consultas a los distintos tipos de usuarios

@app.post("/registerDon")
async def register_user(
    user_name: str = Form(...),
    last_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    phone_number: str = Form(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    image: Optional[UploadFile] = File(None)
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="El correo ya está registrado.")
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        image_url = None
        if image:
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/{UPLOAD_DIR}/{image.filename}"
        
        
        sql = """
        INSERT INTO donors (user_name, last_name, email, pasword, phone_numer, is_verified, is_admin, images) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (user_name, last_name, email, hashed_password, phone_number, False, False, image_url)
        cursor.execute(sql, values)
        conn.commit()
        
        token = generar_token_verificacion(email)
        background_tasks.add_task(enviar_correo_verificacion, email, token)
        
        cursor.close()
        conn.close()
        
        return {"message": "Usuario registrado. Verifica tu correo para activar la cuenta."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/registerCen")
async def register_center(
    user_name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    type_center: str = Form(...),  # "comunity_center", "food_bank", "childrens_shelters"
    needs: Optional[str] = Form(None),  # "clothes", "food", "money", opcional
    contact_phone_number: str = Form(...),
    contact_social_media: str = Form(...),
    contact_others: Optional[str] = Form(None),
    address: str = Form(...),
    donations: int = 0,
    background_tasks: BackgroundTasks = BackgroundTasks(),
    image: Optional[UploadFile] = File(None)
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="El correo ya está registrado.")
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        image_url = None
        if image:
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/{UPLOAD_DIR}/{image.filename}"
        
        
        if type_center not in ['comunity_center', 'food_bank', 'childrens_shelters']:
            raise HTTPException(status_code=400, detail="Tipo de centro inválido.")
        
        if needs and needs not in ['clothes', 'food', 'money']:
            raise HTTPException(status_code=400, detail="Necesidad inválida.")
        
        sql = """
        INSERT INTO center (user_name, email, pasword, is_verified, is_admin, contact, addres, type_center, needs, donations, images) 
        VALUES (%s, %s, %s, %s, %s, ROW(%s, %s, %s)::contacts, %s, %s, %s, %s, %s)
        """
        values = (
            user_name, email, hashed_password, False, False,
            contact_phone_number, contact_social_media, contact_others,  # Datos para el tipo compuesto
            address, type_center, needs, donations, image_url
        )
        cursor.execute(sql, values)
        conn.commit()
        
        token = generar_token_verificacion(email)
        background_tasks.add_task(enviar_correo_verificacion, email, token)
        
        cursor.close()
        conn.close()
        
        return {"message": "Centro registrado exitosamente. Verifica tu correo para activar la cuenta."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

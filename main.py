import json
from bson import ObjectId, decode
from fastapi import FastAPI, HTTPException, File, Query, Request, UploadFile, Form
from fastapi import Depends, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi_mail import FastMail, MessageSchema, ConnectionConfig
from pydantic import BaseModel, Field
from datetime import datetime, timedelta
from fastapi import BackgroundTasks
from typing import Literal, Optional
import jwt
from jwt import ExpiredSignatureError, DecodeError
import bcrypt
import os
from pathlib import Path
import shutil
import psycopg2.extras
from psycopg2.extras import RealDictCursor
from pymongo import MongoClient
from dotenv import load_dotenv

#Configuraciones, Metodos y clases a usar, asi como cargar informacion del .env

load_dotenv()
app = FastAPI()
security = HTTPBearer()

UPLOAD_DIR = Path("uploaded_images")
UPLOAD_DIR.mkdir(exist_ok=True)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/uploaded_images", StaticFiles(directory="uploaded_images"), name="uploaded_images")
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

from jwt import decode, ExpiredSignatureError, DecodeError
from fastapi import HTTPException

def validate_center_token(#validacion tokens de centros
    credentials: HTTPAuthorizationCredentials = Security(security)
):
    try:
        # Obtener el token de las credenciales
        token = credentials.credentials
        
        # Decodificar el token (sin el parámetro 'algorithms' directamente)
        payload = decode(token, SECRET_KEY, algorithms=["HS256"])
        
        # Verificar si el token es de tipo "center"
        if payload.get("type") != "center":
            raise HTTPException(status_code=403, detail="No tienes permisos para esta acción")
        
        return payload  # Si es válido, devuelve los datos del token
    
    except ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="El token ha expirado")
    except DecodeError:
        raise HTTPException(status_code=401, detail="Token inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error inesperado: {str(e)}")


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


class News(BaseModel):
    id: Optional[str] = Field(alias="_id")  # El _id de MongoDB
    title: str
    content: str
    public_date: datetime = Field(default_factory=datetime.utcnow)
    image: Optional[str] = None
    status: Literal["urgent", "priority", "events"]
    author: str  # ID del autor (puede ser el ID del usuario "center")


def get_db_connection():
    return psycopg2.connect(
        host=os.getenv('DB_HOST'),
        user=os.getenv('DB_USER'),
        password=os.getenv('DB_PASSWORD'),
        database=os.getenv('DB_NAME'),
        port=os.getenv('DB_PORT')
    )
    
def get_mongo_client():#Conectar con mongo(mongodbAtlas)
    mongo_uri = os.getenv("MONGO_URI")
    return MongoClient(mongo_uri)

client = get_mongo_client()
db = client[os.getenv("MONGO_DB_NAME")]
news_collection = db["news"]

load_dotenv()

def test_mongo_connection():#Testear coneccion con mongo
    try:
        # Crear cliente usando la URI
        mongo_uri = os.getenv("MONGO_URI")
        client = MongoClient(mongo_uri)
        
        # Seleccionar base de datos
        db = client[os.getenv("MONGO_DB_NAME")]
        
        # Probar conexión
        print("Conexión exitosa a MongoDB Atlas")
        print("Bases de datos disponibles:", client.list_database_names())
    except Exception as e:
        print(f"Error al conectar a MongoDB Atlas: {e}")

# Llamar la función
test_mongo_connection()

@app.get("/mongo-data")#Traer todos los objetos de mongo(news)
def get_data_from_mongo():
    client = get_mongo_client()
    db = client[os.getenv("MONGO_DB_NAME")]  # Nombre de la base de datos
    collection = db["news"]       # Nombre de la colección
    
    data = list(collection.find({}, {"_id": 0}))  # Consulta todos los documentos
    return {"data": data}

def generar_token_verificacion(email: str):
    token = jwt.encode(
        {"email": email, "exp": datetime.utcnow() + timedelta(hours=1)},
        SECRET_KEY,
        algorithm="HS256"
    )
    return token

async def enviar_correo_verificacion(email: str, token: str):
    enlace_verificacion = f"http://localhost:4200/verify_email?token={token}"
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

@app.post("/verificar-correo")
async def verificar_correo(request: Request):
    try:
        data = await request.json()
        token = data.get("token")
        if not token:
            raise HTTPException(status_code=400, detail="Token no proporcionado")

        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        email = payload["email"]

        # Actualizar el estado en la base de datos
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
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=400, detail="Token expirado")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token inválido")
    except Exception as e:
        raise HTTPException(status_code=500, detail="Error interno del servidor")

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
        INSERT INTO users (user_name, email, pasword, is_verified, is_admin, is_sponsor, images) 
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        values = (user_name, email, hashed_password, False, False, False, image_url)
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
        
        cursor.execute("SELECT * FROM \"users\" WHERE email = %s", (usr.email,))
        user_record = cursor.fetchone()
        
        if not user_record:
            raise HTTPException(status_code=401, detail="Credenciales incorrectas")
        
        if not user_record[4]:  
            raise HTTPException(status_code=401, detail="Verifica tu correo electrónico antes de iniciar sesión")
        
        if not bcrypt.checkpw(usr.password.encode('utf-8'), user_record[3].encode('utf-8')): 
            raise HTTPException(status_code=401, detail="Contraseña incorrecta")
        
        user_type = "unknown"
        
        cursor.execute("SELECT * FROM \"donors\" WHERE email = %s", (usr.email,))
        if cursor.fetchone():
            user_type = "donor"
        else:
            cursor.execute("SELECT * FROM \"center\" WHERE email = %s", (usr.email,))
            if cursor.fetchone():
                user_type = "center"

        user_data = {
            "id": user_record[0],
            "name": user_record[1],
            "email": user_record[2],
            "is_verified": user_record[4],
            "is_admin": user_record[5]
        }
        images =  user_record[6]
        is_sponsor= user_record[7]
        conn.close()
        
        token = jwt.encode(
            {"sub": usr.email, "exp": datetime.utcnow() + timedelta(hours=1), "type": user_type},
            SECRET_KEY,
            algorithm="HS256"
        )
        
        return {"access_token": token, "token_type": "bearer", "user_type": user_type, "images": images,  "user": user_data, "is_sponsor": is_sponsor}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
   

#Consultas a los distintos tipos de usuarios

@app.delete("/deleteUser/{email}")
async def delete_user(email: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")

        cursor.execute("DELETE FROM users WHERE email = %s", (email,))
        conn.commit()

        # Cerrar conexión
        cursor.close()
        conn.close()
        
        return {"message": "Usuario eliminado exitosamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/user/{email}") #traer usuarios por email (version resumida)
async def get_user(email: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, user_name, email, is_verified, is_admin, is_sponsor, images 
            FROM users 
            WHERE email = %s
        """, (email,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")

        user_data = {
            "user_id": user[0],
            "user_name": user[1],
            "email": user[2],
            "is_verified": user[3],
            "is_admin": user[4],
            "is_sponsor": user[5],
            "images": user[6],
        }

        cursor.close()
        conn.close()
        return {"user": user_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/userId/{user_id}") #traer usuarios por id (version resumida)
async def get_user(user_id: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, user_name, email, is_verified, is_admin, is_sponsor, images 
            FROM users 
            WHERE user_id = %s
        """, (user_id,))
        user = cursor.fetchone()

        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")

        user_data = {
            "user_id": user[0],
            "user_name": user[1],
            "email": user[2],
            "is_verified": user[3],
            "is_admin": user[4],
            "is_sponsor": user[5],
            "images": user[6],
        }

        cursor.close()
        conn.close()
        return {"user": user_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users")  # Traer todos los usuarios
async def get_all_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, user_name, email, is_verified, is_admin, is_sponsor, images
            FROM users
        """)
        users = cursor.fetchall()

        if not users:
            raise HTTPException(status_code=404, detail="No se encontraron usuarios.")

        users_data = [
            {
                "user_id": user[0],
                "user_name": user[1],
                "email": user[2],
                "is_verified": user[3],
                "is_admin": user[4],
                "is_sponsor": user[5],
                "images": user[6],
            }
            for user in users
        ]

        cursor.close()
        conn.close()
        return {"users": users_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

#CRUD donors

@app.get("/donor/{email}")#Traer donantes por email
async def get_donor(email: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT user_id, user_name, last_name, email, phone_numer, is_verified, is_admin, is_sponsor, images 
            FROM donors 
            WHERE email = %s
        """, (email,))
        donor = cursor.fetchone()

        if not donor:
            raise HTTPException(status_code=404, detail="Donante no encontrado.")

        donor_data = {
            "user_id": donor[0],
            "user_name": donor[1],
            "last_name": donor[2],
            "email": donor[3],
            "phone_number": donor[4],
            "is_verified": donor[5],
            "is_admin": donor[6],
            "is_sponsor": donor[7],
            "images": donor[8],
        }

        cursor.close()
        conn.close()
        return {"donor": donor_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

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
        INSERT INTO donors (user_name, last_name, email, pasword, phone_numer, is_verified, is_admin, is_sponsor, images) 
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        values = (user_name, last_name, email, hashed_password, phone_number, False, False, False, image_url)
        cursor.execute(sql, values)
        conn.commit()
        
        token = generar_token_verificacion(email)
        background_tasks.add_task(enviar_correo_verificacion, email, token)
        
        cursor.close()
        conn.close()
        
        return {"message": "Usuario registrado. Verifica tu correo para activar la cuenta."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/updateDonors/{email}")
async def update_donor(
    email: str,
    user_name: Optional[str] = Form(None),
    last_name: Optional[str] = Form(None),
    new_email: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    is_active: Optional[bool] = Form(None),
    is_verified: Optional[bool] = Form(None),
    is_sponsor: Optional[bool] = Form(None),
    phone_number: Optional[str] = Form(None),
    image: Optional[UploadFile] = File(None)
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("SELECT * FROM donors WHERE email = %s", (email,))
        donor = cursor.fetchone()
        if not donor:
            raise HTTPException(status_code=404, detail="Donante no encontrado.")
        
        update_fields = []
        values = []

        if user_name:
            update_fields.append("user_name = %s")
            values.append(user_name)

        if last_name:
            update_fields.append("last_name = %s")
            values.append(last_name)

        if new_email:
            update_fields.append("email = %s")
            values.append(new_email)

        if password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            update_fields.append("pasword = %s")
            values.append(hashed_password)

        if phone_number:
            update_fields.append("phone_numer = %s")
            values.append(phone_number)

        if is_active is not None:
            update_fields.append("is_active = %s")
            values.append(is_active)

        if is_verified is not None:
            update_fields.append("is_verified = %s")
            values.append(is_verified)
            
        if is_sponsor is not None:
            update_fields.append("is_sponsor = %s")
            values.append(is_sponsor)    

        if image:
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/{UPLOAD_DIR}/{image.filename}"
            update_fields.append("images = %s")
            values.append(image_url)
        values.append(email)

        sql = f"UPDATE donors SET {', '.join(update_fields)} WHERE email = %s"
        cursor.execute(sql, values)
        conn.commit()

        cursor.close()
        conn.close()
        
        return {"message": "Donante actualizado exitosamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# CRUD centers

@app.get("/centers")  # Obtener todos los centros con nombre, dirección e imágenes
async def get_all_centers():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                user_name, addres, CONCAT('http://127.0.0.1:8000', images) AS images 
            FROM center
        """)
        centers = cursor.fetchall()

        if not centers:
            raise HTTPException(status_code=404, detail="No se encontraron centros.")
        centers_data = [
            {
                "name": center[0],
                "address": center[1],
                "images": center[2]
            }
            for center in centers
        ]

        cursor.close()
        conn.close()
        return {"centers": centers_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los centros: {str(e)}")

@app.get("/centers/comunity")  # Obtener centros de tipo "comunity_center"
async def get_comunity_centers():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                user_name, addres, CONCAT('http://127.0.0.1:8000', images) AS images 
            FROM center
            WHERE type_center = 'comunity_center'
        """)
        centers = cursor.fetchall()

        if not centers:
            raise HTTPException(status_code=404, detail="No se encontraron centros comunitarios.")
        
        centers_data = [
            {
                "name": center[0],
                "address": center[1],
                "images": center[2]
            }
            for center in centers
        ]

        cursor.close()
        conn.close()
        return {"comunity_centers": centers_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los centros comunitarios: {str(e)}")

@app.get("/centers/bank")  # Obtener centros de tipo "food_bank"
async def get_comunity_centers():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                user_name, addres, CONCAT('http://127.0.0.1:8000', images) AS images 
            FROM center
            WHERE type_center = 'food_bank'
        """)
        centers = cursor.fetchall()

        if not centers:
            raise HTTPException(status_code=404, detail="No se encontraron bancos de alimentos.")
        
        centers_data = [
            {
                "name": center[0],
                "address": center[1],
                "images": center[2]
            }
            for center in centers
        ]

        cursor.close()
        conn.close()
        return {"comunity_centers": centers_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los centros comunitarios: {str(e)}")

@app.get("/centers/shelters")  # Obtener centros de tipo "childrens_shelters"
async def get_comunity_centers():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT 
                user_name, addres, CONCAT('http://127.0.0.1:8000', images) AS images 
            FROM center
            WHERE type_center = 'childrens_shelters'
        """)
        centers = cursor.fetchall()

        if not centers:
            raise HTTPException(status_code=404, detail="No se encontraron casas hogares.")
        
        centers_data = [
            {
                "name": center[0],
                "address": center[1],
                "images": center[2]
            }
            for center in centers
        ]

        cursor.close()
        conn.close()
        return {"comunity_centers": centers_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error al obtener los centros comunitarios: {str(e)}")

@app.get("/center/{email}")#Traer centros por email
async def get_center(email: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                user_id, user_name, email, is_verified, is_admin, is_sponsor, 
                contact, addres, type_center, needs, donations, images 
            FROM center 
            WHERE email = %s
        """, (email,))
        center = cursor.fetchone()

        if not center:
            raise HTTPException(status_code=404, detail="Centro no encontrado.")

        # Extraer el dato de contacto
        contact = center[6]  # Campo compuesto
        contact_phone_number = None
        contact_social_media = None
        contact_others = None

        # Desempaquetar contact si tiene valores
        if contact:
           contact_data = contact.strip("()").split(",")  # Quitar paréntesis y dividir por comas
           contact_phone_number = contact_data[0].strip() if contact_data[0].strip() else None
           contact_social_media = contact_data[1].strip() if len(contact_data) > 1 and contact_data[1].strip() else None
           contact_others = contact_data[2].strip() if len(contact_data) > 2 and contact_data[2].strip() else None

        center_data = {
            "user_id": center[0],
            "user_name": center[1],
            "email": center[2],
            "is_verified": center[3],
            "is_admin": center[4],
            "is_sponsor": center[5],
            "contact": {
                "phone_number": contact_phone_number,
                "social_media": contact_social_media,
                "others": contact_others,
            },
            "address": center[7],
            "type_center": center[8],
            "needs": center[9],
            "donations": center[10],
            "images": center[11],
        }
        cursor.close()
        conn.close()
        return {"center": center_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/centerName/{user_name}")  # Traer centros por nombre (resumida)
async def get_center(user_name: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT 
                user_id, user_name, email, contact, addres, type_center, images 
            FROM center 
            WHERE user_name = %s
        """, (user_name,))
        center = cursor.fetchone()

        if not center:
            raise HTTPException(status_code=404, detail="Centro no encontrado.")

        # Extraer el dato de contacto
        contact = center[3]  # Campo compuesto
        contact_phone_number = None
        contact_social_media = None
        contact_others = None

        # Desempaquetar contact si tiene valores
        if contact:
            contact_data = contact.strip("()").split(",")  # Quitar paréntesis y dividir por comas
            contact_phone_number = contact_data[0].strip() if contact_data[0].strip() else None
            contact_social_media = contact_data[1].strip() if len(contact_data) > 1 and contact_data[1].strip() else None
            contact_others = contact_data[2].strip() if len(contact_data) > 2 and contact_data[2].strip() else None

        center_data = {
            "user_id": center[0],
            "user_name": center[1],
            "email": center[2],
            "contact": {
                "phone_number": contact_phone_number,
                "social_media": contact_social_media,
                "others": contact_others,
            },
            "address": center[4],
            "type_center": center[5],
            "images": center[6]
        }

        cursor.close()
        conn.close()
        return {"center": center_data}

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
    print("Solicitud recibida")
    try:
        print(f"Datos recibidos: user_name={user_name}, email={email}, type_center={type_center}")
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()
        if existing_user:
            raise HTTPException(status_code=400, detail="El correo ya está registrado.")
        
        cursor.execute("SELECT user_id FROM center WHERE user_name = %s", (user_name,))
        existing_center = cursor.fetchone()
        if existing_center:
            raise HTTPException(status_code=400, detail="El nombre del centro ya está registrado.")
        
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        image_url = None
        if image:
            print(f"Archivo recibido: {image.filename}")
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/{UPLOAD_DIR}/{image.filename}"
        else: print("No se recibió archivo.")
        
        type_center = type_center.strip().lower()
        print(f"Valor normalizado de type_center: {type_center}")
        if type_center not in ['comunity_center', 'food_bank', 'childrens_shelters']:
            print("Error: Tipo de centro inválido.")
            raise HTTPException(status_code=400, detail="Tipo de centro inválido.")
        if needs and needs not in ['clothes', 'food', 'money']:
            raise HTTPException(status_code=400, detail="Necesidad inválida.")
        
        sql = """
        INSERT INTO center (user_name, email, pasword, is_verified, is_admin, is_sponsor, contact, addres, type_center, needs, donations, images) 
        VALUES (%s, %s, %s, %s, %s, %s, ROW(%s, %s, %s)::contacts, %s, %s, %s, %s, %s)
        """
        values = (
            user_name, email, hashed_password, False, False,False,
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

@app.put("/updateCenter/{email}") #Aun por componee (En Mantenimiento).
async def update_center(
    email: str,
    user_name: Optional[str] = Form(None),
    new_email: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    type_center: Optional[str] = Form(None),
    needs: Optional[str] = Form(None),
    contact_phone_number: Optional[str] = Form(None),
    contact_social_media: Optional[str] = Form(None),
    contact_others: Optional[str] = Form(None),
    address: Optional[str] = Form(None),
    is_active: Optional[bool] = Form(None),
    is_verified: Optional[bool] = Form(None),
    is_sponsor: Optional[bool] = Form(None),
    image: Optional[UploadFile] = File(None)
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        center = cursor.fetchone()
        if not center:
            raise HTTPException(status_code=404, detail="Centro no encontrado.")
        
        contact_info = center.get("contact")
        if contact_info:
            try:
                contact_info = json.loads(contact_info) if isinstance(contact_info, str) else contact_info
            except json.JSONDecodeError:
                contact_info = {"phone": None, "social_media": None, "others": None}
        else:
            contact_info = {"phone": None, "social_media": None, "others": None}
        
        update_fields = []
        values = []

        if user_name:
            update_fields.append("user_name = %s")
            values.append(user_name)

        if new_email:
            update_fields.append("email = %s")
            values.append(new_email)

        if password:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            update_fields.append("pasword = %s")
            values.append(hashed_password)

        if type_center:
            if type_center not in ['comunity_center', 'food_bank', 'childrens_shelters']:
                raise HTTPException(status_code=400, detail="Tipo de centro inválido.")
            update_fields.append("type_center = %s")
            values.append(type_center)

        if needs:
            if needs not in ['clothes', 'food', 'money']:
                raise HTTPException(status_code=400, detail="Necesidad inválida.")
            update_fields.append("needs = %s")
            values.append(needs)

        if address:
            update_fields.append("addres = %s")
            values.append(address)

        contact_phone = contact_phone_number if contact_phone_number is not None else contact_info.get("phone")
        contact_social = contact_social_media if contact_social_media is not None else contact_info.get("social_media")
        contact_other = contact_others if contact_others is not None else contact_info.get("others")

        update_fields.append("contact = ROW(%s, %s, %s)::contacts")
        values.extend([contact_phone, contact_social, contact_other])

        if image:
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/{UPLOAD_DIR}/{image.filename}"
            update_fields.append("images = %s")
            values.append(image_url)

        if is_active is not None:
            update_fields.append("is_active = %s")
            values.append(is_active)

        if is_verified is not None:
            update_fields.append("is_verified = %s")
            values.append(is_verified)
            
        if is_sponsor is not None:
            update_fields.append("is_sponsor = %s")
            values.append(is_sponsor)

        values.append(email)

        sql = f"UPDATE center SET {', '.join(update_fields)} WHERE email = %s"
        cursor.execute(sql, values)
        conn.commit()

        cursor.close()
        conn.close()
        
        return {"message": "Centro actualizado exitosamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
#Crud de recursos

@app.get("/resource/{resource_id}")#obtener recurso apartir del id
async def getResource(
  resource_id: str  
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE resources_id = %s",(resource_id,))
        resource = cursor.fetchone()

        if not resource:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")

        resource_data = {
            "resources_id": resource[0],
            "center_fk": resource[1],
            "resource_name": resource[2],
            "resource_type": resource[3],
            "amount": resource[4],
            "resource_status": resource[5]
        }
        conn.commit()
        cursor.close()
        conn.close()
        return {"resource": resource_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/registerResource/{center_fk}")
async def register_resource(
    center_fk: int,
    resource_name: str = Form(...),
    resource_type: str = Form(...),  # ENUM: "clothes", "food", "money"
    amount: int = Form(...),
    resource_status: str = Form(...),  # ENUM: "shortage", "urgent", "stocked"
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM center WHERE user_id = %s",(center_fk,))
        resource = cursor.fetchone()
        if not resource:
            raise HTTPException(status_code=404, detail="Centro no encontrado.")

        valid_resource_types = {"clothes", "food", "money"}
        if resource_type not in valid_resource_types:
            raise HTTPException(status_code=400, detail=f"Invalid resource_type. Valid options are: {valid_resource_types}")

        valid_resource_statuses = {"shortage", "urgent", "stocked"}
        if resource_status not in valid_resource_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid resource_status. Valid options are: {valid_resource_statuses}")

        sql = """
        INSERT INTO resources (center_fk, resource_name, resource_type, amount, resource_status) 
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (center_fk, resource_name, resource_type, amount, resource_status)
        cursor.execute(sql, values)
        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Resource registered successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/updateResource/{center_fk}")
async def updateResource(
    center_fk : str,
    resource_name: Optional[str] = Form(None),
    resource_type: Optional[str] = Form(None),# ENUM: "clothes", "food", "money"
    amount: Optional[str] = Form(None),
    resource_status: Optional[str] = Form(None)  # ENUM: "shortage", "urgent", "stocked"
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM center WHERE user_id = %s",(center_fk,))
        center = cursor.fetchone()
        if not center:
            raise HTTPException(status_code=404, detail="Centro no encontrado.")
        
        valid_resource_types = {"clothes", "food", "money"}
        if resource_type not in valid_resource_types:
            raise HTTPException(status_code=400, detail=f"Invalid resource_type. Valid options are: {valid_resource_types}")

        valid_resource_statuses = {"shortage", "urgent", "stocked"}
        if resource_status not in valid_resource_statuses:
            raise HTTPException(status_code=400, detail=f"Invalid resource_status. Valid options are: {valid_resource_statuses}")
        
        update_fields = []
        values = []
        
        if resource_name:
            update_fields.append("resource_name = %s")
            values.append(resource_name)
        if resource_type:
            update_fields.append("resource_type = %s")
            values.append(resource_type)
        if amount:
            update_fields.append("amount = %s")
            values.append(amount)
        if resource_status:
            update_fields.append("resource_status = %s")
            values.append(resource_status)
        
        values.append(center_fk)
        
        sql = f"UPDATE resources SET {', '.join(update_fields)} WHERE center_fk = %s"
        cursor.execute(sql,values)
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "Centro actualizado exitosamente."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.delete("/deleteResource/{resource_id}")
async def deleteResource(
  resource_id: str  
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM resources WHERE resources_id = %s",(resource_id,))
        center = cursor.fetchone()
        if not center:
            raise HTTPException(status_code=404, detail="Resource not found.")
        cursor.execute("DELETE FROM resources WHERE resources_id = %s", (resource_id))
        conn.commit()
        cursor.close()
        conn.close()
        return {"message": "resource removed successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
        
#crud news (in mongodb)
@app.post("/news", dependencies=[Depends(validate_center_token)])
async def create_news(
    title: str = Form(...),
    content: str = Form(...),
    status: Literal["urgent", "priority", "events", "common"] = Form(...),
    image: Optional[UploadFile] = File(None),
    current_user: dict = Depends(validate_center_token)  # Obtén los datos del usuario autenticado
):
    try:
        # Subir la imagen si se proporciona
        image_url = None
        if image:
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/uploaded_images/{image.filename}"

        # Crear el documento de la noticia
        news_data = {
            "title": title,
            "content": content,
            "public_date": datetime.utcnow(),
            "image": image_url,
            "status": status,
            "author": current_user["sub"],  # Email del autor desde el token
        }

        # Insertar en MongoDB
        result = news_collection.insert_one(news_data)
        return {"message": "News created successfully", "news_id": str(result.inserted_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/news/{news_id}", dependencies=[Depends(validate_center_token)])
async def update_news(
    news_id: str,
    new_title: Optional[str] = Form(None),
    content: Optional[str] = Form(None),
    status: Optional[Literal["urgent", "priority", "events"]] = Form(None),
    image: Optional[UploadFile] = File(None),
    current_user: dict = Depends(validate_center_token)
):
    try:
        # Verificar que la noticia existe y pertenece al usuario
        news = news_collection.find_one({"_id": ObjectId(news_id), "author": current_user["sub"]})
        if not news:
            raise HTTPException(status_code=403, detail="No tienes permiso para actualizar esta noticia")

        # Actualizar los campos proporcionados
        update_data = {}
        if new_title:
            update_data["title"] = new_title
        if content:
            update_data["content"] = content
        if status:
            update_data["status"] = status
        if image:
            # Subir la nueva imagen
            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            update_data["image"] = f"/uploaded_images/{image.filename}"

        # Actualizar en MongoDB
        result = news_collection.update_one({"_id": ObjectId(news_id)}, {"$set": update_data})
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="News not found")

        return {"message": "News updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/news/{news_id}", dependencies=[Depends(validate_center_token)])
async def delete_news(news_id: str, current_user: dict = Depends(validate_center_token)):
    try:
        # Verificar que la noticia existe y pertenece al usuario
        news = news_collection.find_one({"_id": ObjectId(news_id), "author": current_user["sub"]})
        if not news:
            raise HTTPException(status_code=403, detail="No tienes permiso para eliminar esta noticia")

        # Eliminar la noticia
        result = news_collection.delete_one({"_id": ObjectId(news_id)})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="News not found")

        return {"message": "News deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/news/special", dependencies=[Depends(validate_center_token)])#crear las noticias especiales
async def create_special_news(
    title: str = Form(...),
    image: UploadFile = File(...),
    current_user: dict = Depends(validate_center_token)  # Obtener los datos del usuario autenticado
):
    try:
        # Verificar y subir la imagen
        if not image:
            raise HTTPException(status_code=400, detail="An image is required")
        
        image_path = UPLOAD_DIR / image.filename
        with image_path.open("wb") as buffer:
            shutil.copyfileobj(image.file, buffer)
        image_url = f"/uploaded_images/{image.filename}"

        news_data = {
            "title": title,
            "public_date": datetime.utcnow(),
            "image": image_url,
            "status": "event",  
            "author": current_user["sub"],  # Email del autor desde el token
        }

        # Insertar en MongoDB
        result = news_collection.insert_one(news_data)
        return {"message": "Simple news created successfully", "news_id": str(result.inserted_id)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/news/special")#traer las noticias que apareceran arriba (solo imagenes y su estatus varia)
async def get_event_news(
    page: int = Query(1, ge=1), 
    page_size: int = Query(10, ge=1, le=100)
):
    try:
        # Calcular los límites para la paginación
        skip = (page - 1) * page_size
        limit = page_size

        # Filtrar noticias con status "event" y obtener resultados paginados
        events = list(
            news_collection.find({"status": "event"})
            .skip(skip)
            .limit(limit)
            .sort("public_date", -1)  # Ordenar por fecha de publicación descendente
        )

        # Convertir ObjectId a string para el cliente
        for event in events:
            event["_id"] = str(event["_id"])

        # Contar el total de documentos con status "event"
        total_events = news_collection.count_documents({"status": "event"})

        return {
            "message": "Event news retrieved successfully",
            "total": total_events,
            "page": page,
            "page_size": page_size,
            "data": events,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/news/secret") #llamar news de donateme (las principales)
async def get_secret_news(
    page: int = Query(1, ge=1), 
    page_size: int = Query(10, ge=1, le=100)
):
    try:
        # Calcular los límites para la paginación
        skip = (page - 1) * page_size
        limit = page_size

        # Filtrar noticias con status "event" y obtener resultados paginados
        events = list(
            news_collection.find({"status": "admin"})
            .skip(skip)
            .limit(limit)
            .sort("public_date", -1)  # Ordenar por fecha de publicación descendente
        )

        # Convertir ObjectId a string para el cliente
        for event in events:
            event["_id"] = str(event["_id"])

        # Contar el total de documentos con status "event"
        total_events = news_collection.count_documents({"status": "event"})

        return {
            "message": "Event news retrieved successfully",
            "data": events,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
#CRUD of needs

@app.post("/registerNeed/{center_fk}")
async def register_need(
    center_fk: int,
    type_need: str = Form(...),  # ENUM: "clothes", "food", "money"
    amount_required: int = Form(...),
    urgency: bool = Form(...),
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM center WHERE user_id = %s", (center_fk,))
        center = cursor.fetchone()
        if not center:
            raise HTTPException(status_code=404, detail="Centro no encontrado.")

        cursor.execute("SELECT COUNT(*) FROM needss WHERE center_fk = %s", (center_fk,))
        need_count = cursor.fetchone()[0]
        max_needs = 2  

        if need_count >= max_needs:
            raise HTTPException(
                status_code=400,
                detail=f"Este centro ya tiene el máximo permitido de {max_needs} necesidades registradas.",
            )
        valid_types = {"clothes", "food", "money"}
        if type_need not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid need_type. Valid options are: {valid_types}",
            )

        cursor.execute(
            "SELECT * FROM needss WHERE center_fk = %s AND need_type = %s",
            (center_fk, type_need),
        )
        existing_need = cursor.fetchone()
        if existing_need:
            raise HTTPException(
                status_code=400,
                detail=f"Este centro ya tiene registrada una necesidad del tipo '{type_need}'.",
            )

        sql = """
        INSERT INTO needss (center_fk, need_type, amount_requered, complete, urgency)
        VALUES (%s, %s, %s, %s, %s)
        """
        values = (center_fk, type_need, amount_required, False, urgency)
        cursor.execute(sql, values)
        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Need registered successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/updateNeed/{need_id}")
async def update_need(
    need_id: int,
    type_need: Optional[str] = Form(None),  # ENUM: "clothes", "food", "money"
    amount_required: Optional[int] = Form(None),
    complete: Optional[bool] = Form(None),
    urgency: Optional[bool] = Form(None),
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM needss WHERE need_id = %s", (need_id,))
        need = cursor.fetchone()
        if not need:
            raise HTTPException(status_code=404, detail="Need not found.")

        valid_types = {"clothes", "food", "money"}
        if type_need and type_need not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid need_type. Valid options are: {valid_types}",
            )

        update_fields = []
        values = []

        if type_need:
            update_fields.append("need_type = %s")
            values.append(type_need)
        if amount_required is not None:
            update_fields.append("amount_requered = %s")
            values.append(amount_required)
        if complete is not None:
            update_fields.append("complete = %s")
            values.append(complete)
        if urgency is not None:
            update_fields.append("urgency = %s")
            values.append(urgency)

        if not update_fields:
            raise HTTPException(status_code=400, detail="No fields to update.")

        values.append(need_id)
        sql = f"UPDATE needss SET {', '.join(update_fields)} WHERE need_id = %s"
        cursor.execute(sql, values)
        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Need updated successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/deleteNeed/{need_id}")
async def delete_need(need_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM needss WHERE need_id = %s", (need_id,))
        need = cursor.fetchone()
        if not need:
            raise HTTPException(status_code=404, detail="Need not found.")

        cursor.execute("DELETE FROM needss WHERE need_id = %s", (need_id,))
        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Need deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/getNeeds")
async def get_all_needs():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM needss")
        needs = cursor.fetchall()

        cursor.close()
        conn.close()

        if not needs:
            raise HTTPException(status_code=404, detail="No needs found.")

        needs_list = [
            {
                "id": need[0],
                "center_fk": need[1],
                "type_need": need[2],
                "amount_required": need[3],
                "complete": need[4],
                "urgency": need[5],
            }
            for need in needs
        ]

        return {"needs": needs_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/getNeeds/{need_id}")
async def get_need(need_id: int):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM needss WHERE need_id = %s", (need_id,))
        need = cursor.fetchone()

        cursor.close()
        conn.close()

        if not need:
            raise HTTPException(status_code=404, detail="Need not found.")
        
        need_data = {
            "id": need[0],
            "center_fk": need[1],
            "type_need": need[2],
            "amount_required": need[3],
            "complete": need[4],
            "urgency": need[5],
        }

        return {"need": need_data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/getNeedsbyName/{user_name}")
async def get_needs_by_center_name(user_name: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT user_id FROM center WHERE user_name = %s", (user_name,))
        center = cursor.fetchone()
        if not center:
            raise HTTPException(
                status_code=404,
                detail=f"Centro con el nombre '{user_name}' no encontrado.",
            )

        center_id = center[0]

        cursor.execute("SELECT * FROM needss WHERE center_fk = %s", (center_id,))
        needs = cursor.fetchall()

        cursor.close()
        conn.close()

        if not needs:
            raise HTTPException(
                status_code=404,
                detail=f"No se encontraron necesidades para el centro '{user_name}'.",
            )

        needs_list = [
            {
                "need_id": need[0],
                "center_fk": need[1],
                "type_need": need[2],
                "amount_required": need[3],
                "complete": need[4],
                "urgency": need[5],
            }
            for need in needs
        ]

        return {"center_name": user_name, "needs": needs_list}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/getNeedsbyNT/{user_name}/{type_need}")
async def get_needs_by_name_and_type(user_name: str, type_need: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Obtener el ID del centro basado en el nombre
        cursor.execute("SELECT user_id FROM center WHERE user_name = %s", (user_name,))
        center = cursor.fetchone()
        if not center:
            raise HTTPException(
                status_code=404,
                detail=f"Centro con el nombre '{user_name}' no encontrado.",
            )

        center_id = center[0]

        # Filtrar necesidades por el centro y el tipo de necesidad
        cursor.execute(
            "SELECT * FROM needss WHERE center_fk = %s AND need_type = %s",
            (center_id, type_need),
        )
        needs = cursor.fetchall()

        cursor.close()
        conn.close()

        if not needs:
            raise HTTPException(
                status_code=404,
                detail=f"No se encontraron necesidades del tipo '{type_need}' para el centro '{user_name}'.",
            )

        needs_list = [
            {
                "need_id": need[0],
                "center_fk": need[1],
                "need_type": need[2],
                "amount_required": need[3],
                "complete": need[4],
                "urgency": need[5],
            }
            for need in needs
        ]

        return {
            "center_name": user_name,
            "need_type": type_need,
            "needs": needs_list,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


#Crud del diavlo

@app.post("/registerDonation/{donor_fk}/{need_fk}")
async def register_donation(
    donor_fk: str,
    need_fk: str,
    type_donation: str = Form(...),
    comentary: str = Form(...),
    amount: int = Form(...),
    image: UploadFile = File(None)  # Hacemos que la imagen sea opcional
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM donors WHERE user_id = %s", (donor_fk,))
        donor = cursor.fetchone()
        if not donor:
            raise HTTPException(status_code=404, detail="Donante no encontrado.")

        cursor.execute("SELECT * FROM needss WHERE need_id = %s", (need_fk,))
        need = cursor.fetchone()
        if not need:
            raise HTTPException(status_code=404, detail="Necesidad no encontrada.")

        valid_type_donation = {"clothes", "food", "money"}
        if type_donation not in valid_type_donation:
            raise HTTPException(status_code=400, detail=f"Tipo de donación inválido. Opciones válidas: {valid_type_donation}")

        amount_required = need[3]
        if amount > amount_required:
            raise HTTPException(
                status_code=400,
                detail=f"La cantidad excede lo requerido. Necesidad actual: {amount_required}",
            )

        new_amount = amount_required - amount

        image_url = None  # Inicializamos image_url como None por si no se sube imagen

        if image:  # Procesamos la imagen solo si se proporciona
            UPLOAD_DIR = Path("uploaded_images")
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            image_url = f"/uploaded_images/{image.filename}"

        try:
            donation_sql = """
            INSERT INTO donations (donor_id, type_donation, complete, comentary, image)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING donation_id
            """
            donation_values = (donor_fk, type_donation, False, comentary, image_url)
            cursor.execute(donation_sql, donation_values)

            donation_id = cursor.fetchone()[0]

            amount_sql = """
            INSERT INTO amount (donation_fk, needs_fk, amount)
            VALUES (%s, %s, %s)
            """
            amount_values = (donation_id, need_fk, amount)
            cursor.execute(amount_sql, amount_values)

            update_need_sql = """
            UPDATE needss SET amount_requered = %s WHERE need_id = %s
            """
            update_need_values = (new_amount, need_fk)
            cursor.execute(update_need_sql, update_need_values)

            conn.commit()

        except Exception as e:
            conn.rollback()
            raise e

        cursor.close()
        conn.close()

        return {"message": "Donación registrada exitosamente."}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/donations/")
async def get_donations(donor_id: str = None, need_id: str = None):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        base_query = "SELECT d.donation_id, d.donor_id, d.complete, d.type_donation, d.comentary, d.image, a.amount, n.need_id, n.amount_requered FROM donations d INNER JOIN amount a ON d.donation_id = a.donation_fk INNER JOIN needss n ON a.needs_fk = n.need_id"
        conditions = []
        values = []

        if donor_id:
            conditions.append("d.donor_id = %s")
            values.append(donor_id)
        if need_id:
            conditions.append("n.need_id = %s")
            values.append(need_id)

        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)

        cursor.execute(base_query, tuple(values))
        donations = cursor.fetchall()

        # Formatear resultados
        donations_list = [
            {
                "donation_id": donation[0],
                "donor_id": donation[1],
                "complete": donation[2],
                "type_donation": donation[3],
                "comentary": donation[4],
                "image": donation[5],
                "amount": donation[6],
                "need_id": donation[7],
                "amount_requered": donation[8],
            }
            for donation in donations
        ]

        cursor.close()
        conn.close()

        return donations_list

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/donations/{donor_id}")
async def get_donations_by_donor(donor_id: str):
    try:
        # Conexión a la base de datos
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Consulta SQL para obtener todas las donaciones del usuario por su donor_id
        query = """
        SELECT 
            d.donation_id, 
            d.donor_id, 
            d.complete, 
            d.type_donation, 
            d.comentary, 
            d.image, 
            a.amount, 
            n.need_id, 
            n.amount_requered
        FROM donations d
        INNER JOIN amount a ON d.donation_id = a.donation_fk
        INNER JOIN needss n ON a.needs_fk = n.need_id
        WHERE d.donor_id = %s
        """
        cursor.execute(query, (donor_id,))
        donations = cursor.fetchall()

        # Formatear resultados
        donations_list = [
            {
                "donation_id": donation[0],
                "donor_id": donation[1],
                "complete": donation[2],
                "type_donation": donation[3],
                "comentary": donation[4],
                "image": donation[5],
                "amount": donation[6],
                "need_id": donation[7],
                "amount_requered": donation[8],
            }
            for donation in donations
        ]

        # Cerrar cursor y conexión
        cursor.close()
        conn.close()

        return donations_list

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/donations/{donation_id}")
async def update_donation(
    donation_id: str,
    new_amount: Optional[int] = Form(None),  # Hacemos que el nuevo monto sea opcional
    comentary: Optional[str] = Form(None),  # Comentario es opcional
    image: Optional[UploadFile] = File(None)  # Imagen es opcional
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT a.amount, a.needs_fk, n.amount_requered, d.image FROM amount a "
            "INNER JOIN needss n ON a.needs_fk = n.need_id "
            "INNER JOIN donations d ON a.donation_fk = d.donation_id "
            "WHERE a.donation_fk = %s",
            (donation_id,),
        )
        donation = cursor.fetchone()
        if not donation:
            raise HTTPException(status_code=404, detail="Donación no encontrada.")

        old_amount, need_fk, current_amount_required, old_image = donation

        # Si se proporciona un nuevo monto, actualizamos el monto y la necesidad
        if new_amount is not None:
            new_amount_requered = current_amount_required + old_amount - new_amount
            if new_amount_requered < 0:
                raise HTTPException(
                    status_code=400,
                    detail="El nuevo monto excede la necesidad restante.",
                )

            # Actualizamos el monto de la donación
            update_amount_sql = "UPDATE amount SET amount = %s WHERE donation_fk = %s"
            cursor.execute(update_amount_sql, (new_amount, donation_id))

            # Actualizamos el monto requerido en la necesidad
            update_need_sql = "UPDATE needss SET amount_requered = %s WHERE need_id = %s"
            cursor.execute(update_need_sql, (new_amount_requered, need_fk))

        # Si se proporciona una nueva imagen, actualizamos la imagen
        new_image_url = old_image
        if image:
            UPLOAD_DIR = Path("uploaded_images")
            UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

            image_path = UPLOAD_DIR / image.filename
            with image_path.open("wb") as buffer:
                shutil.copyfileobj(image.file, buffer)
            new_image_url = f"/uploaded_images/{image.filename}"

        # Si se proporciona un nuevo comentario, lo actualizamos
        update_donation_sql = """
            UPDATE donations 
            SET comentary = COALESCE(%s, comentary), image = %s
            WHERE donation_id = %s
        """
        cursor.execute(update_donation_sql, (comentary, new_image_url, donation_id))

        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Donación actualizada exitosamente."}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/donationsComplete/{donation_id}")
async def toggle_donation_complete(donation_id: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verificar si la donación existe
        cursor.execute(
            "SELECT complete FROM donations WHERE donation_id = %s",
            (donation_id,)
        )
        donation = cursor.fetchone()

        if not donation:
            raise HTTPException(status_code=404, detail="Donación no encontrada.")

        current_complete = donation[0]

        # Alternar el estado de 'complete'
        new_complete = not current_complete

        # Actualizar el estado en la base de datos
        cursor.execute(
            "UPDATE donations SET complete = %s WHERE donation_id = %s",
            (new_complete, donation_id)
        )
        conn.commit()

        cursor.close()
        conn.close()

        return {
            "message": "Estado de 'complete' actualizado exitosamente.",
            "donation_id": donation_id,
            "new_complete": new_complete
        }

    except Exception as e:
        if conn:
            conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/donations/{donation_id}")
async def delete_donation(donation_id: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute(
            "SELECT a.amount, a.needs_fk, n.amount_requered FROM amount a INNER JOIN needss n ON a.needs_fk = n.need_id WHERE a.donation_fk = %s",
            (donation_id,),
        )
        donation = cursor.fetchone()
        if not donation:
            raise HTTPException(status_code=404, detail="Donación no encontrada.")

        amount, need_fk, current_amount_required = donation

        new_amount_requered = current_amount_required + amount

        cursor.execute("DELETE FROM amount WHERE donation_fk = %s", (donation_id,))
        cursor.execute("DELETE FROM donations WHERE donation_id = %s", (donation_id,))

        update_need_sql = "UPDATE needss SET amount_requered = %s WHERE need_id = %s"
        cursor.execute(update_need_sql, (new_amount_requered, need_fk))

        conn.commit()

        cursor.close()
        conn.close()

        return {"message": "Donación eliminada exitosamente."}

    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/donationsRan/ranking")
async def get_donation_ranking():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        ranking_sql = """
        SELECT 
            d.user_id AS donor_id,
            COALESCE(COUNT(don.donation_id), 0) AS total_donations,
            d.images AS donor_image,
            d.user_name AS donor_name,
            d.is_sponsor  
        FROM 
            donors d
        LEFT JOIN 
            donations don ON d.user_id = don.donor_id
            AND don.complete = TRUE
        GROUP BY 
            d.user_id, d.is_sponsor, d.images, d.user_name
        """
        cursor.execute(ranking_sql)
        ranking = cursor.fetchall()

        if not ranking:
            raise HTTPException(status_code=404, detail="No se encontraron donantes.")

        result = []
        for row in ranking:
            donor_id, total_donations, donor_image, donor_name, is_sponsor = row
            if is_sponsor:
                total_donations += 10
            result.append({
                "donor_id": donor_id,
                "total_donations": total_donations,
                "donor_image": donor_image,
                "donor_name": donor_name
            })

        result = sorted(result, key=lambda x: x['total_donations'], reverse=True)

        top_donor_info = result[0] if result else None

        cursor.close()
        conn.close()

        return {
            "ranking": result,
            "top_donor": top_donor_info
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/centers/comunityNeeds/{need_type}/{urgency}", response_model=dict)  # Con filtros (CUANDO SE INSTANCIE, ESTOS METODOS NECESITAN NUEVA UPDATE)
@app.get("/centers/comunityNeeds", response_model=dict)  # Sin filtros
async def get_comunity_centers_with_needs(
    need_type: str | None = None, 
    urgency: bool | None = None
):
    try:
        # Validar que el need_type sea válido si está presente
        valid_need_types = {"money", "food", "clothes"}
        if need_type and need_type not in valid_need_types:
            raise HTTPException(
                status_code=400,
                detail=f"El tipo de necesidad '{need_type}' no es válido. Use uno de: {', '.join(valid_need_types)}"
            )
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Construir la consulta base
        base_query = """
            SELECT 
                c.user_name AS center_name,
                c.addres AS address,
                CONCAT('http://127.0.0.1:8000', c.images) AS image,
                n.need_type AS need_type,
                n.amount_requered AS amount_requered,
                n.urgency AS urgency
            FROM center c
            JOIN needss n ON c.user_id = n.center_fk
            WHERE c.type_center = 'comunity_center'
            AND n.amount_requered > 0
        """
        
        # Agregar filtros dinámicos
        filters = []
        params = []
        
        if need_type:
            filters.append("n.need_type = %s")
            params.append(need_type)
        
        if urgency is not None:  # Urgencia explícita (True/False)
            filters.append("n.urgency = %s")
            params.append(urgency)
        
        # Combinar filtros en la consulta si existen
        if filters:
            base_query += " AND " + " AND ".join(filters)
        
        # Ejecutar la consulta
        cursor.execute(base_query, tuple(params))
        centers = cursor.fetchall()

        # Validar resultados
        if not centers:
            raise HTTPException(
                status_code=404, 
                detail="No se encontraron centros comunitarios con los filtros especificados."
            )

        # Construir la respuesta
        centers_data = [
            {
                "center_name": center[0],
                "address": center[1],
                "image": center[2],
                "need_type": center[3],
                "amount_required": center[4],
                "urgency": center[5],
            }
            for center in centers
        ]

        # Cerrar la conexión
        cursor.close()
        conn.close()
        return {"centers": centers_data}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener los centros comunitarios con necesidades: {str(e)}"
        )



@app.get("/centers/bankNeeds/{need_type}/{urgency}", response_model=dict)  # Food_bank con filtro opcional
@app.get("/centers/bankNeeds", response_model=dict)  # Food_bank sin filtro
async def get_food_bank_centers_with_needs(
    need_type: str | None = None, 
    urgency: bool | None = None
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        base_query = """
            SELECT 
                c.user_name AS center_name,
                c.addres AS address,
                CONCAT('http://127.0.0.1:8000', c.images) AS image,
                n.need_type AS need_type,
                n.amount_requered AS amount_requered,
                n.urgency AS urgency
            FROM center c
            JOIN needss n ON c.user_id = n.center_fk
            WHERE c.type_center = 'food_bank'
            AND n.amount_requered > 0
        """
        
        filters = []
        if need_type:
            filters.append("n.need_type = %s")
        if urgency is not None:
            filters.append("n.urgency = %s")
        
        if filters:
            base_query += " AND " + " AND ".join(filters)
        
        params = tuple(param for param in [need_type, urgency] if param is not None)
        cursor.execute(base_query, params)
        centers = cursor.fetchall()

        if not centers:
            raise HTTPException(
                status_code=404, 
                detail="No se encontraron bancos de alimentos con los filtros especificados."
            )

        centers_data = [
            {
                "center_name": center[0],
                "address": center[1],
                "image": center[2],
                "need_type": center[3],
                "amount_required": center[4],
                "urgency": center[5],
            }
            for center in centers
        ]

        cursor.close()
        conn.close()
        return {"centers": centers_data}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener los bancos de alimentos con necesidades: {str(e)}"
        )


@app.get("/centers/sheltersNeeds/{need_type}/{urgency}", response_model=dict)  # Childrens_shelters con filtro opcional
@app.get("/centers/sheltersNeeds", response_model=dict)  # Childrens_shelters sin filtro
async def get_shelters_with_needs(
    need_type: str | None = None, 
    urgency: bool | None = None
):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        base_query = """
            SELECT 
                c.user_name AS center_name,
                c.addres AS address,
                CONCAT('http://127.0.0.1:8000', c.images) AS image,
                n.need_type AS need_type,
                n.amount_requered AS amount_requered,
                n.urgency AS urgency
            FROM center c
            JOIN needss n ON c.user_id = n.center_fk
            WHERE c.type_center = 'childrens_shelters'
            AND n.amount_requered > 0
        """
        
        filters = []
        if need_type:
            filters.append("n.need_type = %s")
        if urgency is not None:
            filters.append("n.urgency = %s")
        
        if filters:
            base_query += " AND " + " AND ".join(filters)
        
        params = tuple(param for param in [need_type, urgency] if param is not None)
        cursor.execute(base_query, params)
        centers = cursor.fetchall()

        if not centers:
            raise HTTPException(
                status_code=404, 
                detail="No se encontraron casas hogares con los filtros especificados."
            )

        centers_data = [
            {
                "center_name": center[0],
                "address": center[1],
                "image": center[2],
                "need_type": center[3],
                "amount_required": center[4],
                "urgency": center[5],
            }
            for center in centers
        ]

        cursor.close()
        conn.close()
        return {"centers": centers_data}

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Error al obtener las casas hogares con necesidades: {str(e)}"
        )

@app.get("/users/sponsors")  # Traer todos los patrocinadores
async def get_all_sponsors():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, user_name, email, is_verified, is_admin, is_sponsor, images
            FROM users
            WHERE is_sponsor = TRUE
        """)
        sponsors = cursor.fetchall()

        if not sponsors:
            raise HTTPException(status_code=404, detail="No se encontraron patrocinadores.")

        sponsors_data = [
            {
                "user_id": user[0],
                "user_name": user[1],
                "email": user[2],
                "is_verified": user[3],
                "is_admin": user[4],
                "is_sponsor": user[5],
                "images": user[6],
            }
            for user in sponsors
        ]

        cursor.close()
        conn.close()
        return {"sponsors": sponsors_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/sponsors3")  # Traer los tres primeros patrocinadores
async def get_top_three_sponsors():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, user_name, email, is_verified, is_admin, is_sponsor, images
            FROM users
            WHERE is_sponsor = TRUE
            ORDER BY user_id ASC
            LIMIT 3
        """)
        top_sponsors = cursor.fetchall()

        if not top_sponsors:
            raise HTTPException(status_code=404, detail="No se encontraron patrocinadores.")

        top_sponsors_data = [
            {
                "user_id": user[0],
                "user_name": user[1],
                "email": user[2],
                "is_verified": user[3],
                "is_admin": user[4],
                "is_sponsor": user[5],
                "images": user[6],
            }
            for user in top_sponsors
        ]

        cursor.close()
        conn.close()
        return {"top_sponsors": top_sponsors_data}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/ConvertSponsor/{email}")#Convertir o quitar en sponsor a alguien (todo tipo de usuarios)
async def toggle_sponsor_status(email: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)

        # Obtener el estado actual del donante
        cursor.execute("SELECT is_sponsor FROM donors WHERE email = %s", (email,))
        donor = cursor.fetchone()
        if not donor:
            raise HTTPException(status_code=404, detail="Donante no encontrado.")
        
        # Alternar el valor de is_sponsor
        new_status = not donor['is_sponsor']
        
        # Actualizar el valor en la base de datos
        cursor.execute(
            "UPDATE donors SET is_sponsor = %s WHERE email = %s",
            (new_status, email)
        )
        conn.commit()

        cursor.close()
        conn.close()
        
        return {
            "message": "Estado de patrocinador actualizado exitosamente.",
            "email": email,
            "is_sponsor": new_status
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/deleteCenter/{email}")#Eliminar usuarios tipo centros, (se conservan las donaciones indicando como null al borrar sus datos de amount)
async def delete_center(email: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("SELECT user_id FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="Usuario no encontrado.")
        
        cursor.execute("SELECT need_id FROM needss WHERE center_fk = %s", (user['user_id'],))
        needs = cursor.fetchall()

        if needs:
            for need in needs:
                cursor.execute("UPDATE amount SET needs_fk = NULL WHERE needs_fk = %s", (need['need_id'],))

        cursor.execute("DELETE FROM needss WHERE center_fk = %s", (user['user_id'],))

        cursor.execute("DELETE FROM users WHERE email = %s", (email,))
        conn.commit()

        cursor.close()
        conn.close()
        
        return {"message": "Centro y sus necesidades eliminados exitosamente, donaciones conservadas."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

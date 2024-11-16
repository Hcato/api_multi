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
import psycopg2.extras
from psycopg2.extras import RealDictCursor
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
            "is_admin": user_record[5],
            "is_sponsor": user_record[6]
        }
        conn.close()
        
        token = jwt.encode(
            {"sub": usr.email, "exp": datetime.utcnow() + timedelta(hours=1), "type": user_type},
            SECRET_KEY,
            algorithm="HS256"
        )
        
        return {"access_token": token, "token_type": "bearer", "user_type": user_type, "user": user_data}
    
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
async def get_user(gmail: str):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT user_id, user_name, email, is_verified, is_admin, is_sponsor, images 
            FROM users 
            WHERE email = %s
        """, (gmail,))
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
        
#crud donations inprogress
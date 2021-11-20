import json
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from datetime import datetime, timedelta
from typing import Optional
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

class List():
    role: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    email: Optional[str] = None
    full_name: Optional[str] = None
    disabled: Optional[bool] = None

class UserInDB(User):
    hashed_password: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

with open("menu.json", "r") as read_file:
    data = json.load(read_file)
read_file.close()

with open("user.json", "r") as read_file:
    fake_users_db = json.load(read_file)
read_file.close()

app = FastAPI(description ="Login Account Tutee")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict) #supposed to be hash keknya

def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(fake_users_db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

async def curr_username(current_user: User = Depends(get_current_active_user)):
    return current_user.username

async def isCurrUsername(username: str, current_user: User = Depends(get_current_active_user)):
    if username==current_user.username:
        return(True)
    else:
        return(False)

@app.get('/menu', tags=["Admin View"])
async def read_all_menu(current_user: User = Depends(get_current_active_user)):
    return data

@app.get('/user', tags=["Manajemen Akun"])
async def read_user_data(current_user: User = Depends(get_current_active_user)):
    return fake_users_db

@app.post('/menu', tags=["Admin View"])
async def post_menu(name:str, current_user: User = Depends(get_current_active_user)):
    id=1
    if(len(data['menu'])>0):
        id=data['menu'][len(data['menu'])-1]['id']+1
    new_data={'id':id,'name':name}
    data['menu'].append(dict(new_data))
    
@app.post('/RegisterAdmin', tags=["Manajemen Akun"])
async def register_admin(username:str, password:str, current_user: User = Depends(get_current_active_user)):
    if username not in fake_users_db:
        new_data = {"username": username, "hashed_password": get_password_hash(password),"disabled": False}
    fake_users_db[username] = new_data
    read_file.close()
    with open("user.json", "w") as write_file:
        json.dump(fake_users_db,write_file,indent=4)
    write_file.close()
    return (new_data)

@app.get('/menu/{item_id}', tags=["Admin View"])
async def update_menu(item_id: int, name:str, current_user: User = Depends(get_current_active_user)):
    for menu_item in data['menu']:
        if menu_item['id'] == item_id:
            menu_item['name']=name
        read_file.close()
        with open("menu.json", "w") as write_file:
            json.dump(data,write_file,indent=4)
        write_file.close()
        return{"message": "Data updated successfully"}
    raise HTTPException(
        status_code=404, detail=f'Item not found'
    )

@app.post('/DaftarHarga', tags=["Menu Pengguna"])
async def Baca_List_Harga():
    return(data)

@app.post("/token", response_model=Token, tags=["Others"])
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get('/resetpassword/', tags=["Manajemen Akun"])
async def reset_password(current_password: str, password:str,current_user: User = Depends(get_current_active_user)):
    if verify_password(current_password,(fake_users_db[current_user.username])['hashed_password']):
        (fake_users_db[current_user.username])['hashed_password'] = get_password_hash(password)
        with open("user.json", "w") as write_file:
            json.dump(fake_users_db,write_file,indent=4)
        write_file.close()
        return('Password berhasil diubah!')
    else:
        return('Password salah!')